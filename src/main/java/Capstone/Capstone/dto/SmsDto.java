package Capstone.Capstone.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Service;

@Setter
@Getter
public class SmsDto {
    private String phoneNumber;
    private String verificationCode
    ;
}
