package Capstone.Capstone.servicelmpl;
import Capstone.Capstone.dto.CommentDto;
import Capstone.Capstone.entity.Comment;
import Capstone.Capstone.entity.Community;
import Capstone.Capstone.repository.CommentRepository;
import Capstone.Capstone.repository.CommunityRepository;
import Capstone.Capstone.service.CommentService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Slf4j
@Service
public class CommentServiceImpl implements CommentService {

    private final CommentRepository commentRepository;
    private final CommunityRepository communityRepository;



    @Autowired
    public CommentServiceImpl(CommentRepository commentRepository, CommunityRepository communityRepository) {
        this.commentRepository = commentRepository;
        this.communityRepository=communityRepository;


    }



    @Override
    public Comment addComment(CommentDto commentDto) {
            log.info("CommunityID{},comment{}",commentDto.getCommunityId(),commentDto.getComment());
            Optional<Community> OptionalCommunity = communityRepository.findById(commentDto.getCommunityId());
            if (OptionalCommunity.isPresent()) {
                Community findCommunity = OptionalCommunity.get();
                Comment comment=convertToEntity(commentDto);
                log.info("id={}",comment.getId());
                findCommunity.getComments().add(comment);
                comment.setCommunity(findCommunity);
                return commentRepository.save(comment);
            }

       return null;


    }

    @Override
    public Comment getCommentById(Long id) {
        return commentRepository.findById(id).orElse(null);
    }

    @Override
    public void deleteComment(Long id) {
        commentRepository.deleteById(id);
    }

    @Override
    public Comment convertToEntity(CommentDto commentDto) {
        Comment comment=new Comment();
        comment.setComment(commentDto.getComment());
        comment.setNickName(commentDto.getNickName());
        comment.setTime(commentDto.getTime());
        comment.setId(0L);
        return comment;
    }

    @Override
    public Long allCommentById(Long communityId) {
       return commentRepository.countCommentsByCommunityId(communityId);
    }

}
