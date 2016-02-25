package gateway.test;

import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import gateway.controller.GatewayController;

import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;

import model.data.DataResource;
import model.data.type.RasterResource;
import model.job.Job;
import model.job.JobProgress;
import model.job.type.GetJob;
import model.job.type.IngestJob;
import model.request.PiazzaJobRequest;
import model.response.JobStatusResponse;
import model.response.PiazzaResponse;
import model.status.StatusUpdate;

import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import util.PiazzaLogger;
import util.UUIDFactory;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Tests the Gateway Controller. This will test synchronous and asynchronous
 * jobs.
 * 
 * @author Patrick.Doody
 * 
 */
public class GatewayControllerTests {
	@Mock
	private PiazzaLogger logger;
	@Mock
	private UUIDFactory uuidFactory;
	@Mock
	private RestTemplate restTemplate;
	@Mock
	private Producer<String, String> producer;
	@Mock
	private AmazonS3 s3Client;
	@InjectMocks
	private GatewayController gatewayController;

	private Job mockIngestJob;
	private PiazzaJobRequest mockRequest;

	/**
	 * Initialize mock objects.
	 */
	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);

		// Mock an Ingest Job
		mockIngestJob = new Job();
		mockIngestJob.jobId = "Test-Job-ID";
		mockIngestJob.status = StatusUpdate.STATUS_RUNNING;
		mockIngestJob.progress = new JobProgress(50);

		// Mock an Ingest Job Request
		RasterResource raster = new RasterResource();
		DataResource data = new DataResource();
		data.dataType = raster;
		IngestJob ingestJob = new IngestJob();
		ingestJob.host = true;
		ingestJob.data = data;
		mockRequest = new PiazzaJobRequest();
		mockRequest.apiKey = "Api-Key";
		mockRequest.jobType = ingestJob;

		// Mock the Kafka response that Producers will send. This will always
		// return a Future that completes immediately and simply returns true.
		when(producer.send(isA(ProducerRecord.class))).thenAnswer(new Answer<Future<Boolean>>() {
			@Override
			public Future<Boolean> answer(InvocationOnMock invocation) throws Throwable {
				Future<Boolean> future = mock(FutureTask.class);
				when(future.isDone()).thenReturn(true);
				when(future.get()).thenReturn(true);
				return future;
			}
		});
	}

	/**
	 * Tests the fetching of a Job Status for our Mock Ingest Job via the
	 * synchronous Dispatcher REST API.
	 * 
	 * @throws JsonProcessingException
	 */
	@Test
	public void testSynchronousJob() throws JsonProcessingException {
		// Mocking a Status Response for fetching Job Status from the Dispatcher
		JobStatusResponse mockResponse = new JobStatusResponse(mockIngestJob);
		PiazzaJobRequest mockRequest = new PiazzaJobRequest();
		mockRequest.apiKey = UUID.randomUUID().toString();
		mockRequest.jobType = new GetJob(mockIngestJob.jobId);
		String request = new ObjectMapper().writeValueAsString(mockRequest);

		// When the Gateway asks the Dispatcher for Job Status, Mock that
		// response here.
		when(restTemplate.getForObject(anyString(), eq(PiazzaResponse.class))).thenReturn(mockResponse);

		// Testing the Job Status Response to Ensure equality with our Mock Data
		PiazzaResponse response = gatewayController.job(request, null);
		assertTrue(response.getType().equals(mockResponse.getType()));
		JobStatusResponse jobResponse = (JobStatusResponse) response;
		assertTrue(jobResponse.jobId.equals(mockIngestJob.jobId));
		assertTrue(jobResponse.progress.getPercentComplete().equals(mockIngestJob.progress.getPercentComplete()));
		assertTrue(jobResponse.status.equals(mockIngestJob.status));
	}

	/**
	 * Tests inserting a Job into the system and returning a Job creation
	 * response, using the Asynchronous Kafka messaging.
	 * 
	 * @throws JsonProcessingException
	 */
	@Test
	public void testAsynchronousJob() throws JsonProcessingException {
		// Mock the inputs for some Ingest Job
		String request = new ObjectMapper().writeValueAsString(mockRequest);

		// Mock a GUID produced from the UUIDGen service
		String guid = UUID.randomUUID().toString();
		when(uuidFactory.getUUID()).thenReturn(guid);

		// Ensure a new Job was created with the matching Job ID
		PiazzaResponse response = gatewayController.job(request, null);
		assertTrue(response.getType().equals("job"));
		assertTrue(response.jobId.equals(guid));
	}

	/**
	 * Tests the appropriate upload of a file to the Gateway.
	 * 
	 * @throws JsonProcessingException
	 */
	@Test
	public void testFileIngest() throws JsonProcessingException, IOException {
		// Mock the inputs for some sample Ingest Job
		String request = new ObjectMapper().writeValueAsString(mockRequest);
		// Mock a test file. The contents are irrelevant.
		MockMultipartFile file = new MockMultipartFile("test.tif", "Content".getBytes());

		// Mock values for the @Value fields used by AWS S3 Client. These cannot
		// be null.
		ReflectionTestUtils.setField(gatewayController, "AMAZONS3_ACCESS_KEY", "access.test");
		ReflectionTestUtils.setField(gatewayController, "AMAZONS3_PRIVATE_KEY", "private.test");
		ReflectionTestUtils.setField(gatewayController, "AMAZONS3_BUCKET_NAME", "bucket.test");

		// Mock the S3 Client method for inserting a file into an S3 Bucket.
		when(s3Client.putObject(anyString(), anyString(), isA(InputStream.class), isA(ObjectMetadata.class)))
				.thenReturn(null);
		String guid = UUID.randomUUID().toString();
		when(uuidFactory.getUUID()).thenReturn(guid);

		// Create a request with the File
		PiazzaResponse response = gatewayController.job(request, file);
		assertTrue(response.getType().equals("job"));
		assertTrue(response.jobId.equals(guid));
	}
}