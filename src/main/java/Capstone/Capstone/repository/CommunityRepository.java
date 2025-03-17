package Capstone.Capstone.repository;

import Capstone.Capstone.entity.Community;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CommunityRepository extends JpaRepository<Community,Long> {
    List<Community> findTop5ByOrderByLikeCountDesc();
    List<Community> findByTitle(String title);

    List<Community> findByTitleContaining(String title);
    List<Community> findAllByOrderByIdDesc();

}

