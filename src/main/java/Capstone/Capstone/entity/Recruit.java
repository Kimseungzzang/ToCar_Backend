package Capstone.Capstone.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@Entity
public class Recruit {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int idxNum;
    private String title;
    private String contents;
    private String nickname;
    private String id;
    private double star=0.0;
    private double avgStar=0.0;

    @ElementCollection
    private List<String> keywords = new ArrayList<>(); //키워드

    private String destination; //목적지
    private String departure;
    private LocalDate departureDate; //출발일자
    private int distance2; //사용자 실시간 위치에서 모집글 사용자 위치까지 거리
    private String time;
    private int distance; //사용자 실시간 위치에서 모집글 사용자 위치까지 거리

    private boolean isDriverPost; //운전자가 작성한 글인지 아닌지
    private int participant;
    private int maxParticipant;

    private String message;
    @ElementCollection
    private List<String> users = new ArrayList<>();
    @ElementCollection
    private List<String> bookingUsers=new ArrayList<>();
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt; //생성날짜
    @Column(nullable = false)
    private LocalDateTime updatedAt; //수정날짜
    private double  departureX;
    private double  departureY;
    private double arrivalX;
    private double arrivalY;
    @ManyToMany
    @JoinTable(name = "record",
            joinColumns = @JoinColumn(name = "recruit_id"),
            inverseJoinColumns = @JoinColumn(name = "user_nickname"))
    private List<User> bookedUsers;

    private boolean Full=false;

    private double currentX;
    private double currentY;
    private double timeTaxi;
    private int fare;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }



    public void setIsDriverPost(boolean isDriverPost) {
        this.isDriverPost = isDriverPost;
    }






}

