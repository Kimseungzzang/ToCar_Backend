package Capstone.Capstone.repository;

import Capstone.Capstone.entity.Like;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LikeRepository extends JpaRepository<Like,Long> {
    List<Like> findByCommunityIdAndUserId(Long postId, String userId);
}
