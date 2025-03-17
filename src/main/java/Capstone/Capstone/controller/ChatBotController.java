package Capstone.Capstone.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.json.JSONObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;

@RestController
@RequestMapping("/api")
public class ChatBotController {

    private final String GPT_API_URL = "https://api.openai.com/v1/chat/completions";

    @Value("${openai.api.key}")
    private String API_KEY;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @PostMapping("/chatBot")
    public String chat(@RequestBody String message) {
        try {
            // 요청 헤더 설정
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(GPT_API_URL))
                    .header("Authorization", "Bearer " + API_KEY)  // API 키를 헤더에 추가
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            new JSONObject()
                                    .put("model", "gpt-3.5-turbo")
                                    .put("messages", Arrays.asList(
                                            new JSONObject()
                                                    .put("role", "system")
                                                    .put("content", "You are a helper at a carpool site" +
                                                            " You can only speak Korean.  If you ask the distance from anywhere or the time" +
                                                            " it takes, tell me the distance and the time it takes. And if you ask a destination" +
                                                            " in a region, please recommend a tourist attraction in that region."+
                                                            "If ask how to reservation, tell them search in driver booking pages or write a passenger post"
                                                            +"If they ask cost to using carpool, say Find out through chatting with the other person."),
                                            new JSONObject()
                                                    .put("role", "user")
                                                    .put("content", message)
                                    ))
                                    .toString()
                    ))
                    .build();

            // 요청 보내고 응답 받기
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred: " + e.getMessage();
        }
    }

}