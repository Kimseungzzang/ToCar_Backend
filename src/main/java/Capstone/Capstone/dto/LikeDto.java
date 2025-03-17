package Capstone.Capstone.dto;

import Capstone.Capstone.entity.Like;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LikeDto {
    private long id;
    private String userId;
    private long communityId;
    private boolean liked;



}
