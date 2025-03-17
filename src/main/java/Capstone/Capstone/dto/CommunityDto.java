package Capstone.Capstone.dto;

import Capstone.Capstone.entity.Comment;
import Capstone.Capstone.entity.Like;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class CommunityDto {

    private Long id;
    private String title;
    private String content;
    private String nickName;
    private LocalDateTime time;
    private String image;
    private Long likeCount;
    private long clickCount;
    private List<CommentDto> commentsDto;
    private List<LikeDto> likesDto;
    private long commentSum;
}
