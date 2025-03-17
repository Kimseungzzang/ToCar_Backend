package Capstone.Capstone.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CommentDto {
    private String comment;
    private Long communityId;
    private String nickName;
    private String time;
}
