package Capstone.Capstone.repository;

import Capstone.Capstone.entity.Comment;
import Capstone.Capstone.entity.Community;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CommentRepository extends JpaRepository<Comment,Long> {

    @Query("SELECT COUNT(c) FROM Comment c WHERE c.community.id = :communityId")
    Long countCommentsByCommunityId(Long communityId);

}
