package Capstone.Capstone.service;
import Capstone.Capstone.dto.UserDto;
import Capstone.Capstone.entity.User;

public interface UserService {
    void saveUser(User user);

    User getUserById(String Id);


    void updateUserPassword(String Id, String newPassword);
    boolean authenticateUser(String Id, String password);
    String sendSms(User user);

    User getUserByNickName(String nickName);

    boolean checkVerificationCode(String PhoneNum, String verificationCode);
    void switchToDriverMode(User user);

    void registerDriverLicense(User user, String driverLicense);

    void UpdateUserInform(UserDto userDto);

    String saveImage(String image);

    public User convertToEntity(UserDto userDto);

    public  UserDto convertToDto(User user);

    void checkOutUser();

    void addRating(User user, double rating);

}
