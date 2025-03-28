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

import java.time.LocalDateTime;
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

        Random random = new Random();
        int randomNumber = random.nextInt(10000); // 0부터 9999까지의 난수 생성
        return String.format("%04d", randomNumber);
    }

    public SingleMessageSentResponse sendOne(String to, String verificationCode) {
        Message message = new Message();
        message.setFrom("01045729858");
        message.setTo(to);
        message.setText("[ToCar] 아래의 인증번호를 입력해주세요\n" + verificationCode);

        SingleMessageSentResponse response = this.messageService.sendOne(new SingleMessageSendingRequest(message));
        return response;
    }

       public String generateStoreVerificationCode(String phoneNum) {
        String verificationCode = VerificationCode();

        verificationCodes.put(phoneNum, verificationCode);

        // 3분 후에 인증 코드를 삭제하는 스케줄러 실행
        scheduleCodeDeletion(phoneNum);

        log.info("phoneNum={} storedCode={}", phoneNum, verificationCode);
        return verificationCode;
    }
    public boolean checkVerificationCode(String phoneNum, String enteredCode) {

            log.info("phoneNum={}",phoneNum);
            String storedCode = verificationCodes.get(phoneNum);
            log.info("enteredCode={} storedCode={}",enteredCode,storedCode);
            return storedCode != null && storedCode.equals(enteredCode);
        }


    private void scheduleCodeDeletion(String phoneNum) {
        // 5분 후에 인증 코드를 삭제
        long delay = 5 * 60 * 1000;

        new java.util.Timer().schedule(new java.util.TimerTask() {
            @Override
            public void run() {
                verificationCodes.remove(phoneNum);
            }
        }, delay);
    }


}

