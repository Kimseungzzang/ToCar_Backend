package Capstone.Capstone.servicelmpl;


import Capstone.Capstone.service.UserService;



import Capstone.Capstone.dto.UserDto;
import Capstone.Capstone.entity.ChatRoom;
import Capstone.Capstone.entity.User;
import Capstone.Capstone.repository.ChatRoomRepository;

import Capstone.Capstone.service.ChatRoomSerivce;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class ChatRoomServiceImpl implements Capstone.Capstone.service.ChatRoomSerivce {
    private final ChatRoomRepository chatRoomRepository;
    private final UserService userService;

    @Autowired
    ChatRoomServiceImpl(ChatRoomRepository chatRoomRepository, UserService userService){
        this.chatRoomRepository=chatRoomRepository;
        this.userService = userService;
    }
    @Override
    public ChatRoom createChatRoom(UserDto userDto1, UserDto userDto2){

        User user1=userService.convertToEntity(userDto1);
        User user2=userService.convertToEntity(userDto2);
        Set<User> users=new HashSet<>();
        users.add(user1);
        users.add(user2);
        ChatRoom chatRoom=new ChatRoom(users);
        chatRoom.setId(0L);
        log.info("chatroom={}",chatRoom);
        log.info("chatroomId={}",chatRoom.getId());

        chatRoomRepository.save(chatRoom);
        return chatRoom;

    }

    @Override
    public Long getChatRoom(String userId1, String userId2) {
        List<String> users = new ArrayList<>();
        users.add(userId1);
        users.add(userId2);
        List<Long> chatRoomIds = chatRoomRepository.findChatRoomIdByUserIds(users, 2);

        return chatRoomIds.get(0);
    }

    @Override
    public boolean hasChatRoom(String userId1, String userId2) {
        List<String> users = new ArrayList<>();
        users.add(userId1);
        users.add(userId2);
        log.info("{},{}",userId1,userId2);
        List<Long> chatRoomIds = chatRoomRepository.findChatRoomIdByUserIds(users, 2);
        log.info("{}",chatRoomIds);
        if (chatRoomIds.isEmpty()) {
            return false;
        } else
            return true;
    }

    @Override
    public List<Long> getAllChatRoom(String userId) {
        return chatRoomRepository.findChatRoomIdsByUserId(userId);
    }

    @Override
    public String getUserInChatRoom(String userId, long chatRoomId) {

        List<String> otherUserIds = chatRoomRepository.findOtherUserIdsInChatRoom(chatRoomId, userId);


        if ( !otherUserIds.isEmpty()) {
           return otherUserIds.get(0);
        }
        return "";
    }


}
