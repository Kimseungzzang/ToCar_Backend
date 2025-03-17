package Capstone.Capstone.utils;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.nurigo.sdk.NurigoApp;
import net.nurigo.sdk.message.model.Message;
import net.nurigo.sdk.message.request.SingleMessageSendingRequest;
import net.nurigo.sdk.message.response.SingleMessageSentResponse;
import net.nurigo.sdk.message.service.DefaultMessageService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Slf4j
@Component
public class SmsUtil {

    private final Map<String, String> verificationCodes = new HashMap<>();

    @Value("${sms.api.key}")
    private String apiKey;

    @Value("${sms.api.Secretkey}")
    private String apiSecretKey;

    private DefaultMessageService messageService;

    @PostConstruct
    private void init(){
        this.messageService = NurigoApp.INSTANCE.initialize(apiKey, apiSecretKey, "https://api.coolsms.co.kr");
    }


    public static String VerificationCode() {
        // 4자리의 난수 생성
        Random random = new Random();
        int randomNumber = random.nextInt(10000); // 0부터 9999까지의 난수 생성
        return String.format("%04d", randomNumber);
    }


    // 단일 메시지 발송 예제
    public SingleMessageSentResponse sendOne(String to, String verificationCode) {
        Message message = new Message();
        // 발신번호 및 수신번호는 반드시 01012345678 형태로 입력되어야 합니다.
        message.setFrom("01045729858");
        message.setTo(to);
        message.setText("[ToCar] 아래의 인증번호를 입력해주세요\n" + verificationCode);

        SingleMessageSentResponse response = this.messageService.sendOne(new SingleMessageSendingRequest(message));
        return response;
    }

    public String generateStoreVerificationCode(String phoneNum) {
        String verificationCode = VerificationCode();
        verificationCodes.put(phoneNum, verificationCode);
        log.info("phoneNum={} storedCode={}",phoneNum, verificationCodes.get(phoneNum));
        return verificationCode;
    }
    public boolean checkVerificationCode(String phoneNum, String enteredCode) {

            log.info("phoneNum={}",phoneNum);
            String storedCode = verificationCodes.get(phoneNum);
            log.info("enteredCode={} storedCode={}",enteredCode,storedCode);
            return storedCode != null && storedCode.equals(enteredCode);
        }
}