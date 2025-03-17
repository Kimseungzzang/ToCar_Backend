package Capstone.Capstone.servicelmpl;

import Capstone.Capstone.dto.RecruitDto;
import Capstone.Capstone.dto.UserDto;
import Capstone.Capstone.repository.UserRepository;
import Capstone.Capstone.service.RecruitService;
import Capstone.Capstone.entity.Recruit;
import Capstone.Capstone.entity.User;
import Capstone.Capstone.repository.RecruitRepository;
import Capstone.Capstone.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Slf4j

@Service
public class RecruitServiceImpl implements RecruitService {


    private  final UserService userService;
    private  final UserRepository userRepository;
    private final RecruitRepository recruitRepository;
    @Autowired
    private ModelMapper modelMapper;
    @Autowired
    public RecruitServiceImpl(UserService userService, UserRepository userRepository, RecruitRepository recruitRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.recruitRepository = recruitRepository;
    }



    @Override
    public List<RecruitDto> selectDriverBoardList(){

        List<Recruit> recruitList = recruitRepository.findByIsDriverPost(true);
        return recruitList.stream()
                .map(this::ConvertToDto)
                .collect(Collectors.toList());
    }

    @Override
    public List<RecruitDto> selectPassengerBoardList(){

        List<Recruit> recruitList = recruitRepository.findByIsDriverPost(false);
        recruitRepository.findAll(Sort.by(Sort.Direction.DESC, "createdAt"));
        return recruitList.stream()
                .map(this::ConvertToDto)
                .collect(Collectors.toList());

    }

    @Override
    public RecruitDto getRecruitById(Long id){
        Optional<Recruit> opRecruit = recruitRepository.findById(id);
       if( opRecruit.isPresent()){
           RecruitDto recruitDto=ConvertToDto(opRecruit.get());
           return  recruitDto;
       }
       return null;
    }

    @Override
    public Recruit createRecruit(RecruitDto recruitDto){

      Recruit recruit= ConvertToEntity(recruitDto);
      recruit.setAvgStar(userRepository.findByNickname(recruitDto.getNickname()).getAvgStar());
      recruit.setFull(false);
        return recruitRepository.save(recruit);
    }

    @Override
    public void deleteRecruit(Long id){
        recruitRepository.deleteById(id);
    }

    @Override
    public Recruit updateRecruit(Long id, Recruit recruitDetails) {
        Optional<Recruit> recruitOptional = recruitRepository.findById(id);

        if (!recruitOptional.isPresent()) {
            return null;
        }

        Recruit recruit = recruitOptional.get();
        recruit.setTitle(recruitDetails.getTitle());
        recruit.setContents(recruitDetails.getContents());
        recruit.setNickname(recruitDetails.getNickname());

        recruit.setStar(recruitDetails.getStar());


        recruitRepository.save(recruit);
        return recruit;
    }

    @Override
    public List<Recruit> findLatestRecruits() {
        return recruitRepository.findAllByOrderByCreatedAtDesc();
    }

    @Override
    public List<Recruit> searchRecruits(LocalDate departureDate, String destination) {
        return recruitRepository.findByDepartureDateAndDestination(departureDate, destination);
    }
    @Override
    public List<Recruit> findRecruitsByDistance(double userLat, double userLon) {
        List<Recruit> allRecruits = recruitRepository.findAll();
        return allRecruits.stream()
                .sorted(Comparator.comparing(recruit -> calculateDistance(userLat, userLon, recruit.getDepartureX(), recruit.getDepartureY())))
                .collect(Collectors.toList());
    }

    @Override
    public int calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        double distance;
        double radius = 6371; // 지구 반지름(km)
        double toRadian = Math.PI / 180;

        double deltaLatitude = Math.abs(lat1 - lat2) * toRadian;
        double deltaLongitude = Math.abs(lon1 - lon2) * toRadian;

        double sinDeltaLat = Math.sin(deltaLatitude / 2);
        double sinDeltaLng = Math.sin(deltaLongitude / 2);
        double squareRoot = Math.sqrt(
                sinDeltaLat * sinDeltaLat +
                        Math.cos(lat1 * toRadian) * Math.cos(lat2 * toRadian) * sinDeltaLng * sinDeltaLng);

        distance = 2 * radius * Math.asin(squareRoot);


        return (int)distance;
    }

    @Override
    public List<Recruit> findRecruitsByKeywords(List<String> keywords){
        return recruitRepository.findByKeywordsIn(keywords);
    }


    @Override
    public Recruit ConvertToEntity(RecruitDto recruitDto) {
        Recruit recruit=new Recruit();
        recruit.setCreatedAt(recruitDto.getCreatedAt());
        recruit.setContents(recruitDto.getContents());
        recruit.setDestination(recruitDto.getDestination());
        recruit.setDeparture(recruitDto.getDeparture());
        recruit.setDepartureDate(recruitDto.getDepartureDate());
        recruit.setKeywords(recruitDto.getKeywords());
        recruit.setTitle(recruitDto.getTitle());
        recruit.setMessage(recruitDto.getMessage());
        recruit.setNickname(recruitDto.getNickname());
        recruit.setParticipant(recruitDto.getParticipant());
        recruit.setMaxParticipant(recruitDto.getMaxParticipant());
        recruit.setUsers(recruitDto.getUsers());
        recruit.setBookingUsers(recruitDto.getBookingUsers());
        recruit.setIsDriverPost(recruitDto.isDriverPost());
        recruit.setArrivalX(recruitDto.getArrivalX());
        recruit.setArrivalY(recruitDto.getArrivalY());
        recruit.setDepartureY(recruitDto.getDepartureY());
        recruit.setDepartureX(recruitDto.getDepartureX());
        recruit.setIdxNum(recruitDto.getIdxNum());
        recruit.setDistance(recruitDto.getDistance());
        recruit.setDistance2(recruitDto.getDistance2());
        recruit.setAvgStar(recruitDto.getAvgStar());
        recruit.setCurrentX(recruitDto.getCurrentX());
        recruit.setCurrentY(recruitDto.getCurrentY());
        recruit.setTime(recruitDto.getTime());
        recruit.setFare(recruitDto.getFare());
        recruit.setId(recruitDto.getId());
        recruit.setTimeTaxi(recruitDto.getTimeTaxi());
        recruit.setFull(recruitDto.isFull());
        log.info("{}",recruitDto.getNickname());

        return recruit;
    }

    @Override
    public RecruitDto ConvertToDto(Recruit recruit) {
        RecruitDto recruitDto = new RecruitDto();
        recruitDto.setCreatedAt(recruit.getCreatedAt());
        recruitDto.setContents(recruit.getContents());
        recruitDto.setDestination(recruit.getDestination());
        recruitDto.setDeparture(recruit.getDeparture());
        recruitDto.setDepartureDate(recruit.getDepartureDate());
        recruitDto.setDistance2(recruit.getDistance2());
        recruitDto.setKeywords(recruit.getKeywords());
        recruitDto.setTitle(recruit.getTitle());
        recruitDto.setMessage(recruit.getMessage());
        recruitDto.setNickname(recruit.getNickname());
        recruitDto.setParticipant(recruit.getParticipant());
        recruitDto.setMaxParticipant(recruit.getMaxParticipant());
        recruitDto.setUsers(recruit.getUsers());
        recruitDto.setBookingUsers(recruit.getBookingUsers());
        recruitDto.setDriverPost(recruit.isDriverPost());
        recruitDto.setArrivalX(recruit.getArrivalX());
        recruitDto.setArrivalY(recruit.getArrivalY());
        recruitDto.setDepartureY(recruit.getDepartureY());
        recruitDto.setDepartureX(recruit.getDepartureX());
        recruitDto.setId(recruit.getId());
        recruitDto.setTime(recruit.getTime());

        recruitDto.setDistance(recruit.getDistance());
        recruitDto.setIdxNum(recruit.getIdxNum());

        recruitDto.setAvgStar(recruit.getAvgStar());

        recruitDto.setCurrentX(recruit.getCurrentX());
        recruitDto.setCurrentY(recruit.getCurrentY());
        recruitDto.setTimeTaxi(recruit.getTimeTaxi());
        recruitDto.setFare((recruit.getFare()));
        User user=userRepository.findByNickname(recruit.getNickname());
        UserDto userDto=new UserDto();
        userDto.setProfileImage(user.getProfileImage());
        userDto.setAvgStar(user.getAvgStar());
        recruitDto.setUserDto(userDto);
        recruitDto.setFull(recruit.isFull());



        return recruitDto;
    }

    @Override
    public void addParticipant(Long idxNum) {
        Optional<Recruit> Oprecruit=recruitRepository.findById(idxNum);
        if(Oprecruit.isPresent())
        {
            Recruit recruit=Oprecruit.get();
            recruit.setParticipant(recruit.getParticipant()+1);

        }
    }

    @Override
    public boolean addBookingList(String user,Long idxNum) {
        Optional<Recruit> Oprecruit = recruitRepository.findById(idxNum);

        if (Oprecruit.isPresent()) {
            Recruit recruit = Oprecruit.get();
            List<User> findusers = recruit.getBookedUsers();
            if (findusers == null) {
                findusers = new ArrayList<>();
            }

            List<String> users = recruit.getUsers();
            List<String> bookingUsers = recruit.getBookingUsers();
            if (!users.contains(user) && !bookingUsers.contains(user)) {

                users.add(user);
                recruit.setUsers(users);
                User findUser = userRepository.findByNickname(user);
                if (findUser != null) {
                    List<Recruit> recruits = findUser.getRecruits();
                    recruits.add(recruit);
                    findusers.add(findUser);
                    findUser.setRecruits(recruits);
                    userRepository.save(findUser);
                    log.info("Saved records for user: {}", findUser.getRecruits());
                } else {
                    log.error("User with nickname {} not found.", user);
                }
            }
            else {
                return false;
            }
            recruit.setBookedUsers(findusers);

            recruitRepository.save(recruit);
            return true;
        }
        return false;

    }

    @Override
    public void subBookingList(String user,Long idxNum) {
        Optional<Recruit> Oprecruit=recruitRepository.findById(idxNum);
        if(Oprecruit.isPresent())
        {
            Recruit recruit=Oprecruit.get();
            List<String> users= recruit.getUsers();
            List<String> bookingUsers= recruit.getBookingUsers();
            users.remove(user);
            bookingUsers.add(user);
            recruit.setBookingUsers(bookingUsers);
            recruit.setUsers(users);
            recruit.setFull(true);
            recruitRepository.save(recruit);
            log.info("bookingusers:{}",bookingUsers);

        }
    }



    @Override
    public void addBookingRecord(Recruit recruit) {
        List<String> users = recruit.getBookingUsers();

        List<User> findusers=recruit.getBookedUsers();
        if (findusers == null) {
            findusers = new ArrayList<>();
        }
        log.info("예약 인원들:{}", users);

        for (String userNickname : users) {
            User findUser = userRepository.findByNickname(userNickname);
            log.info("찾은 인원:{}",findUser);
            if (findUser != null) {
                List<Recruit> recruits = findUser.getRecruits();
                recruits.add(recruit);
                findusers.add(findUser);
                findUser.setRecruits(recruits);
                userRepository.save(findUser);
                log.info("Saved records for user: {}", findUser.getRecruits());
            } else {
                log.error("User with nickname {} not found.", userNickname);
            }
        }
        recruit.setBookedUsers(findusers);
        recruitRepository.save(recruit);
    }

    @Override
    public List<RecruitDto> getBookingRecord(String nickname) {
        User user=userRepository.findByNickname(nickname);

     List<Recruit> recruits=user.getRecruits();

     List<RecruitDto> recruitDtos = new ArrayList<>();
     for(Recruit recruit:recruits){
         RecruitDto recruitDto=ConvertToDto(recruit);
         recruitDtos.add(recruitDto);
     }
     return recruitDtos;
    }

    @Override
    public void addRecruitRating(Long recruitId, double star) {
        Recruit recruit = recruitRepository.findById(recruitId).orElse(null);
        if (recruit == null) {
            throw new IllegalArgumentException("Recruit not found with ID: " + recruitId);
        }

        double totalStars = recruit.getAvgStar() * recruit.getStar();
        totalStars += star;
        double newStarCount = recruit.getStar() + 1;
        double newAvgStar = totalStars / newStarCount;

        recruit.setStar(newStarCount);
        recruit.setAvgStar(newAvgStar);

        recruitRepository.save(recruit);
    }


    @Override
    public int calculateTaxiFare(double distance, double time){
        final double BASE_FARE = 4800; // 기본 요금
        final double PER_KM_RATE = 763; // km당 요금
        final double PER_MINUTE_RATE = 50; // 분당 요금

        time = distance / 60; //평균속도 60km로 가정하고 계산
        double distanceFare = distance > 1 ? (distance - 1) * PER_KM_RATE : 0;
        double timeFare = time * PER_MINUTE_RATE;

        return (int) (BASE_FARE + distanceFare + timeFare);
    }

}





