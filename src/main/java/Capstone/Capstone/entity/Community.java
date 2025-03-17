package Capstone.Capstone.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@AllArgsConstructor
@Entity
@Getter
@Setter
public class Community {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String content;
    private String nickName;
    private LocalDateTime time;
    private String image;
    private Long likeCount;
    private long clickCount;


    @OneToMany(mappedBy = "community", fetch = FetchType.EAGER, cascade = CascadeType.REMOVE)
    @OrderBy("id asc") // 댓글 정렬
    private List<Comment> comments;


    @OneToMany(mappedBy = "community",cascade = CascadeType.REMOVE)
    private List<Like> likes;
    public Community() {

    }


}
