package Capstone.Capstone.service;

import Capstone.Capstone.dto.RecruitDto;
import Capstone.Capstone.entity.Recruit;
import Capstone.Capstone.entity.User;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
public interface RecruitService {
    List<RecruitDto> selectDriverBoardList();
    List<RecruitDto> selectPassengerBoardList();

    RecruitDto getRecruitById(Long id);

    Recruit createRecruit(RecruitDto recruitDto);

    void deleteRecruit(Long id);

    Recruit updateRecruit(Long id, Recruit recruitDetails);

    List<Recruit> findLatestRecruits();

    List<Recruit> searchRecruits(LocalDate departureDate, String destination);

    List<Recruit> findRecruitsByDistance(double userLat, double userLon);

    int calculateDistance(double lat1, double lon1, double lat2, double lon2);

    List<Recruit> findRecruitsByKeywords(List<String> keywords);

    Recruit ConvertToEntity(RecruitDto recruitDto);

    RecruitDto ConvertToDto(Recruit recruit);
    void addParticipant(Long idxNum);
    boolean addBookingList(String user, Long idxNum);
    void subBookingList(String user, Long idxNum);

    void addBookingRecord(Recruit recruit);

   

    List<RecruitDto> getBookingRecord(String nickname);

    int calculateTaxiFare(double distance, double time);

    void addRecruitRating(Long recruitId, double star);

}
