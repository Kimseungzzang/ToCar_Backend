package Capstone.Capstone.controller;


import Capstone.Capstone.entity.User;
import Capstone.Capstone.service.UserService;

import Capstone.Capstone.dto.CreateRoomDto;
import Capstone.Capstone.dto.UserDto;
import Capstone.Capstone.entity.ChatRoom;
import Capstone.Capstone.service.ChatRoomSerivce;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api")
public class ChatRoomController {

    private final UserService userService;
    private final ChatRoomSerivce chatRoomSerivce;
    @Autowired
    public ChatRoomController(UserService userService,ChatRoomSerivce chatRoomSerivce) {
        this.userService = userService;
        this.chatRoomSerivce=chatRoomSerivce;
    }


    @PostMapping("/Chat")
    public ResponseEntity<Long> CreateChatRoom (@RequestBody CreateRoomDto createRoomDto){

        UserDto user1=UserDto.convertToDto(userService.getUserByNickName(createRoomDto.getUserId1()));
        UserDto user2=UserDto.convertToDto(userService.getUserByNickName(createRoomDto.getUserId2()));
        Long chatRoomId;
        if(chatRoomSerivce.hasChatRoom(user1.getNickname(),user2.getNickname())) {
           chatRoomId=chatRoomSerivce.getChatRoom(user1.getNickname(),user2.getNickname());
            return new ResponseEntity<>(chatRoomId, HttpStatus.OK);
        }
        else {
            ChatRoom chatRoom = chatRoomSerivce.createChatRoom(user1, user2);
            chatRoomId=chatRoom.getId();
            return new ResponseEntity<>(chatRoomId, HttpStatus.OK);
        }

    }
    @GetMapping("/getChatRoomNumber")
    public ResponseEntity<Long> GetChatRoomNumber(@RequestParam String userId1,@RequestParam String userId2){
        return new ResponseEntity<>(chatRoomSerivce.getChatRoom(userId1,userId2),HttpStatus.OK);
    }

    @GetMapping("/getAllChatRoomNumber")
    public ResponseEntity<List<UserDto>>GetAllChatRoomNumber(@RequestParam String userId){

        List<Long>chatRooms=chatRoomSerivce.getAllChatRoom(userId);

        List<UserDto> allOtherUsers = new ArrayList<>();

        for (Long chatRoomId : chatRooms) {
           String username = chatRoomSerivce.getUserInChatRoom(userId, chatRoomId);
           log.info("아이디:{},채팅방번호:{}",userId,chatRoomId);
           User user=userService.getUserByNickName(username);
           UserDto userDto=new UserDto();
           userDto.setNickname(user.getNickname());
           userDto.setAvgStar(user.getAvgStar());
           userDto.setProfileImage(user.getProfileImage());
            allOtherUsers.add(userDto);
            log.info("user={}",userDto);
        }
        return new ResponseEntity<>(allOtherUsers,HttpStatus.OK);
    }



}
