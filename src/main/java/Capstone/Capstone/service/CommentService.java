package Capstone.Capstone.service;

import Capstone.Capstone.dto.CommentDto;
import Capstone.Capstone.entity.Comment;

public interface CommentService {
     Comment addComment(CommentDto commentDto);
     Comment getCommentById(Long id);
     void deleteComment(Long id);

     Comment convertToEntity(CommentDto commentDto);

     Long allCommentById(Long communityId);

}