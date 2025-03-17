package Capstone.Capstone.repository;

import Capstone.Capstone.dto.RecruitDto;
import Capstone.Capstone.entity.Recruit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface RecruitRepository extends JpaRepository<Recruit, Long> {
    List<Recruit> findAllByOrderByCreatedAtDesc(); //최신 모집글 찾기 쿼리 메서드
    List<Recruit> findByDepartureDateAndDestination(LocalDate departureDate, String destination); //출발일자, 목적지, 출발 위치에 기반한 검색을 수행
    List<Recruit> findByKeywordsIn(List<String> keywords); //키워드로 검색. 여러 키워드를 넣고 그 중에 하나라도 포함돼있는 글은 모두 가져온다

    List<Recruit> findByIsDriverPost(boolean isDriverPost);

}
