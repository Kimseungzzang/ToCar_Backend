package Capstone.Capstone.servicelmpl;

import Capstone.Capstone.dto.UserDto;
import Capstone.Capstone.entity.Community;
import Capstone.Capstone.entity.User;
import Capstone.Capstone.utils.SmsUtil;
import Capstone.Capstone.repository.UserRepository;
import Capstone.Capstone.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private final SmsUtil smsUtil;


    @Autowired
    public UserServiceImpl(UserRepository userRepository,SmsUtil smsUtil) {
        this.userRepository = userRepository;
        this.smsUtil=smsUtil;
    }

    @Override
    public void saveUser(User user) {
        userRepository.save(user);

    }

    @Override
    public User getUserById(String Id) {
        Optional<User> optionalUser = userRepository.findById(Id);
        log.info("{}",optionalUser);
        return optionalUser.orElse(null);
    }
    @Override
    public void updateUserPassword(String Id, String newPassword) {

        Optional<User> optionalUser = userRepository.findById(Id);

        optionalUser.ifPresent(existingUser -> {
            log.info("userId={} pw={}",Id,newPassword);
            existingUser.setPassword(newPassword);
            userRepository.save(existingUser);
        });
    }

    @Override
    public boolean authenticateUser(String Id, String password) {
        Optional<User> optionalUser = userRepository.findById(Id);
        return optionalUser.isPresent() && optionalUser.get().getPassword().equals(password);
    }


    @Override
    public String sendSms(User user) {


            //수신번호 형태에 맞춰 "-"을 ""로 변환
            String phoneNum = user.getPhoneNumber().replaceAll("-","");



            String verificationCode = smsUtil.generateStoreVerificationCode(phoneNum);
            smsUtil.sendOne(phoneNum, verificationCode);


            return "SMS 전송 성공";
        }

    @Override
    public User getUserByNickName(String nickName) {
        return userRepository.findByNickname(nickName);
    }

    @Override
        public boolean checkVerificationCode(String phoneNum,String verificationCode){
            phoneNum=phoneNum.replaceAll("-","");

           return smsUtil.checkVerificationCode(phoneNum,verificationCode);

        }
    @Override
    public void switchToDriverMode(User user) {
        if (user.getDriverLicense() == null || user.getDriverLicense().isEmpty()) {
            throw new IllegalStateException("운전면허증을 등록해야 운전자 모드를 사용할 수 있습니다.");
        }
        user.setIsDriver(true);
        userRepository.save(user);
    }

    @Override
    public void registerDriverLicense(User user, String driverLicense) { //면허증 등록
        user.setDriverLicense(driverLicense);
        userRepository.save(user);
    }



    @Override
    public void UpdateUserInform(UserDto userDto) {
        Optional<User> user=userRepository.findById(userDto.getId());
        if (user.isPresent()){
           User findUser=user.get();

           findUser.setNickname(userDto.getNickname());
           findUser.setBirthdate(userDto.getBirthdate());
           findUser.setPhoneNumber(userDto.getPhoneNumber());
           findUser.setName(userDto.getName());
           findUser.setId(userDto.getId());
           findUser.setAvgStar(userDto.getAvgStar());
           findUser.setProfileImage(saveImage(userDto.getProfileImage()));
           userRepository.save(findUser);
        }

    }

    @Override
    public void checkOutUser() {


    }

    @Override
    public User convertToEntity(UserDto userDto) {
        User user = new User();
        user.setId(userDto.getId());
        user.setNickname(userDto.getNickname());
        return user;
    }
@Override
    public UserDto convertToDto(User user){

        UserDto userDto=new UserDto();
        userDto.setName(user.getName());
        userDto.setId(user.getId());
        userDto.setBirthdate(user.getBirthdate());
        userDto.setNickname(user.getNickname());
        userDto.setPhoneNumber(user.getPhoneNumber());
        userDto.setProfileImage(user.getProfileImage());
        userDto.setAvgStar(user.getAvgStar());
        return userDto;
}
    @Override
    public String saveImage(String image) {
        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String fileName = "image_" + timeStamp + ".jpg"; // 파일 확장자에 맞게 변경

        // 이미지 데이터(dataURL) 추출
        String imageData = image;

        // dataURL에서 실제 데이터 부분만 분리 (콤마 이후의 부분)
        String base64Image = imageData.split(",")[1];

        // base64로 인코딩된 데이터를 디코딩하여 바이너리 데이터로 변환
        byte[] imageBytes = Base64.getDecoder().decode(base64Image);
        String imageUrl="/home/ubuntu/images/"+fileName;

        // 저장할 파일 경로 지정
        File outputFile = new File(imageUrl);

        try (OutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(imageBytes);
        }

        catch (Exception e) {
            e.printStackTrace();

        }
        return  imageUrl;
    }

    @Override
    public void addRating(User user, double star) {
        double totalStar = user.getAvgStar() * user.getStar();
        totalStar += star;
        int newStarCount = user.getStar() + 1;
        double newAverageStar = totalStar / newStarCount;

        user.setStar(newStarCount);
        user.setAvgStar(newAverageStar);

        userRepository.save(user);
    }





}

