package Capstone.Capstone.entity;


import Capstone.Capstone.dto.RecruitDto;
import Capstone.Capstone.entity.Comment;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Getter
@Setter
public class User {
    @Id
    @Column(name = "id")
    private String id;

    private String name;
    private Date birthdate;
    private String phoneNumber;
    private String profileImage;
    private String password;
    private String nickname;

    private boolean isDriver; //현재 운전자 모드인지 아닌지
    private String driverLicense; //운전면허증 등록여부
    private int star=0;
    private double avgStar = 0.0; //별점 평균

    @ManyToMany(mappedBy = "bookedUsers")
    private List<Recruit> recruits;

    public void setIsDriver(boolean isDriver) {
        this.isDriver = isDriver;
    }


    // 생성자, getter, setter 등 필요한 코드 추가


    @OneToMany(mappedBy = "user")
    private List<Like> likes;

    @ManyToMany(mappedBy = "users")
    private Set<ChatRoom> chatRooms = new HashSet<>();



}
