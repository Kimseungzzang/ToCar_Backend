package Capstone.Capstone.controller;


import Capstone.Capstone.dto.SmsDto;
import Capstone.Capstone.dto.UserDto;
import Capstone.Capstone.entity.User;


import Capstone.Capstone.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;



@Slf4j
@RestController
@RequestMapping("/api/user")
@Tag(name="User API",description = "User API입니다.")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }



    @PostMapping("/signUp")
    @Tag(name = "User API")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "유저 셍성")
    })
    @Operation(summary = "회원가입", description = "User 정보를 저장합니다.")
    public ResponseEntity<Void> signUp(@RequestBody User user) {
        userService.saveUser(user);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @GetMapping("/getUser/{userId}")
    @Tag(name = "User API")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "유저 확인"),
            @ApiResponse(responseCode = "400", description = "유효하지 않은 유저"),
    })
    @Operation(summary = "회원 찾기", description = "id를 기반으로 user를 찾습니다.")
    public ResponseEntity<UserDto> getUserById(@PathVariable("userId") String userId) {
        UserDto userDto = userService.convertToDto(userService.getUserById(userId));
        if (userDto != null) {
            return new ResponseEntity<>(userDto, HttpStatus.OK);
        }
        return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/login")
    @Tag(name = "User API")
    @Operation(summary = "로그인", description = "id와 password를 기반으로 로그인합니다.")
    public ResponseEntity<Void> login(@RequestBody UserDto userDto, HttpServletRequest request) {
        String Id = userDto.getId();
        String password = userDto.getPassword();


        User findUser = userService.getUserById(Id);
        boolean isAuthenticated = userService.authenticateUser(Id, password);

        if (isAuthenticated) {

            HttpSession session = request.getSession(true);

            // 현재 기기 정보
            String currentDevice = request.getHeader("User-Agent");
            String previousDevice = (String) session.getAttribute("device");

            // 기존 세션과 기기 정보 비교
            if (previousDevice != null && !previousDevice.equals(currentDevice)) {
                // 기기 정보가 다르면 기존 세션을 무효화하고 로그아웃 처리
                session.invalidate(); // 기존 세션 종료

                // 새로운 세션 생성
                session = request.getSession(true);
                session.setAttribute("id", findUser.getId());
                session.setAttribute("nickname", findUser.getNickname());
                session.setAttribute("device", currentDevice); // 새로운 기기 정보 저장
            } else {
                // 동일 기기에서 로그인한 경우
                session.setAttribute("id", findUser.getId());
                session.setAttribute("nickname", findUser.getNickname());
                session.setAttribute("device", currentDevice); // 동일 기기 정보 저장
            }

            return new ResponseEntity<>(HttpStatus.OK); // 로그인 성공
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED); // 로그인 실패
        }
    }


    @GetMapping("/logout")
    @Tag(name="User API")
    @Operation(summary="로그아웃",description = "사용자 세션을 무효화하여 로그아웃시킵니다,")
    public void logOut(@CookieValue (value = "JSSEIONID",defaultValue = "")String sessionId,HttpServletRequest request){
        HttpSession session=request.getSession(false);

        if(session!=null&&session.getId().equals(sessionId)){
            session.invalidate();
        }
    }

    @GetMapping("/checkId")
    public ResponseEntity<Boolean> checkId(@RequestParam String id){
        if(userService.getUserById(id)!=null)
        {
            return new ResponseEntity<>(false,HttpStatus.OK);
        }
        return new ResponseEntity<>(true,HttpStatus.OK);
    }


    @PostMapping("/findPw")
    @Tag(name = "User API")
    @Operation(summary = "비밀번호 찾기", description = "비밀번호를 찾습니다.")
    public ResponseEntity<Void> findPassword(@RequestBody User user) {
        userService.sendSms(user);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PutMapping("/changePassword/{userId}")
    @Tag(name = "User API")
    @Operation(summary = "비밀번호 변경", description = "password를 변경합니다")
    public ResponseEntity<Void> changePassword(@PathVariable("userId") String userId, @RequestParam String newPassword) {
        userService.updateUserPassword(userId, newPassword);
        return new ResponseEntity<>(HttpStatus.OK);
    }
    @PutMapping("/changeInform")
    public  ResponseEntity<Void> changeUserInform(@RequestBody UserDto userDto)
    {
        userService.UpdateUserInform(userDto);
        return  new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/sendSMS")
    @Tag(name = "User API")
    @Operation(summary = "sms 발송", description = "userDto의 번호로 인증 문자를 보냅니다")
    public ResponseEntity<Void> sendSMS(@RequestBody User user) {
        userService.sendSms(user);
        return new ResponseEntity<>(HttpStatus.OK);
    }


    @PostMapping("/sendSMS/check")
    @Tag(name = "User API")
    @Operation(summary = "인증문자 확인", description = "입력한 번호가 인증 문자가 맞는지 확인합니다.")
    public boolean checkVerificationCode(@RequestBody SmsDto smsDto) {

        return userService.checkVerificationCode(smsDto.getPhoneNumber(),smsDto.getVerificationCode()) ;


    }

    @PostMapping("/{userId}/switchToDriverMode")
    @Tag(name="User API")
    @Operation(summary = "운전자모드 변경",description = "운전자모드로 전환합니다.")
    public ResponseEntity<Void> switchToDriverMode(@PathVariable String userId) {
        User user = userService.getUserById(userId);
        userService.switchToDriverMode(user);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{userId}/registerDriverLicense")
    @Tag(name="User API")
    @Operation(summary = "운전면허증 등록",description = "운전면허증을 등록합니다.")
    public ResponseEntity<Void> registerDriverLicense(@PathVariable String userId, @RequestBody String driverLicense) {
        User user = userService.getUserById(userId);
        userService.registerDriverLicense(user, driverLicense);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{userId}/star/")
    public ResponseEntity<User> rateUser(@PathVariable String userId, @RequestParam double star) {
        User user = userService.getUserById(userId);

        userService.addRating(user, star);

        return ResponseEntity.ok().build();
    }




}
