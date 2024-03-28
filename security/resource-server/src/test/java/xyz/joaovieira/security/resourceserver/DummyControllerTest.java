package xyz.joaovieira.security.resourceserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import xyz.joaovieira.security.resourceserver.models.MyPrincipal;

import java.io.UnsupportedEncodingException;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {SecurityApplication.class})
@AutoConfigureMockMvc
@Import({DummyController.class})
public class DummyControllerTest {

    private static final String JWT_TOKEN_VALID = "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX0NMSUVOVCJdLCJhdXRoVHlwZSI6ImFwaSIsImV4cCI6MjcxMTA1MzI3MiwidXNlcklkIjoidXNlcl9pZF8xMjM0NSJ9.By5guJ1PF-BoFR457KW6W5wcp8qclSVdYeXcQDv60L79iCvJs_IHau04XwWJk2hkISC-eXIsZyXOgGcBn2kOhg";
    private static final String JWT_TOKEN_EXPIRED = "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX0NMSUVOVCJdLCJhdXRoVHlwZSI6ImFwaSIsImV4cCI6MTcxMTA1MzI3MiwidXNlcklkIjoidXNlcl9pZF8xMjM0NSJ9.EQ82LhBw1hvQ10LajO7Rl3xBfCjKvaUTvVL8SYV1uMTahG08LFU6R1M0sNGdsFveQ0vXBZj9Di9LKCpNL2scjg";
    private static final String JWT_TOKEN_INVALID = "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX0NMSUVOVCJdLCJhdXRoVHlwZSI6ImFwaSIsImV4cCI6MTcxMTA1MzI3MiwidXNlcklkIjoidXNlcl9pZF8xMjM0NSJ9.y2A9fAI7wUIxN4VpeVQet-OyVwlqA6gvQ9o7NNy67-QSEEzjM8TnDCLUDjK8hDWXQx-QqN3mGlG8jovCbu1Pk3";
    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldTestWithoutAuthentication() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/secure"))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void shouldTestWithAnonymousUser() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/secure"))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }


    @Test
    void shouldTestSecuredEndpointWithTokenExpired() throws Exception {
        // Create a request with the token in the Authorization header
        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders.get("/api/secure")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + JWT_TOKEN_EXPIRED);

        // Perform the request and expect an OK response
        mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void shouldTestSecuredEndpointWithTokenInvalidSignature() throws Exception {
        // Create a request with the token in the Authorization header
        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders.get("/api/secure")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + JWT_TOKEN_INVALID);

        // Perform the request and expect an OK response
        mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    void shouldTestSecuredEndpointWorkingToken() throws Exception {
        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders.get("/api/secure")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + JWT_TOKEN_VALID)
                .contentType(MediaType.APPLICATION_JSON);

        mockMvc.perform(requestBuilder)
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(result -> {
                    MyPrincipal principal = convertResultInPrincipal(result);

                    //asserts that the principal is correct based on the token passed
                    assertThat(principal).isNotNull();
                    assertThat(principal.getAuthType()).isEqualTo("api");
                    assertThat(principal.getUserId()).isEqualTo("user_id_12345");
                    assertThat(principal.getRoles()).contains("ROLE_CLIENT");
                });
    }

    @Test
    void testWhitelistedUrlWithAntMatcher() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/user/1235/invite"))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    private static MyPrincipal convertResultInPrincipal(MvcResult result)
            throws JsonProcessingException, UnsupportedEncodingException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper.readValue(result.getResponse().getContentAsString(), MyPrincipal.class);
    }
}
