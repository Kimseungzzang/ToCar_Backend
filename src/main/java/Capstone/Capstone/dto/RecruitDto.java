package Capstone.Capstone.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.cglib.core.Local;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class RecruitDto {
    private int idxNum;
    private String title;
    private String contents;
    private String nickname;
    private int distance;
    private int distance2;
    private String id;
    private double star=0.0;
    private double avgStar=0.0;
    private List<String> keywords;
    private String destination;
    private String departure;
    private LocalDate departureDate;
    private String time;
    private LocalDateTime createdAt;
    private String message;
    private int participant;
    private int maxParticipant;
    private List<String> users;
    private List<String> bookingUsers;
    private boolean isDriverPost;
    private double  departureX;
    private double  departureY;
    private double arrivalX;
    private double arrivalY;
    private double currentX;
    private double currentY;
    private double timeTaxi = 0.0;
    private int fare=0;
    private UserDto userDto;
    private boolean Full;

}

