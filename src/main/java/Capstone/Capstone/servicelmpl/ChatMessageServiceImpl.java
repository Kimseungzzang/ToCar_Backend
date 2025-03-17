package Capstone.Capstone.servicelmpl;


import Capstone.Capstone.service.UserService;
import Capstone.Capstone.dto.ChatMessageDto;
import Capstone.Capstone.entity.ChatMessage;
import Capstone.Capstone.entity.ChatRoom;

import Capstone.Capstone.repository.ChatMessageRepository;
import Capstone.Capstone.repository.ChatRoomRepository;
import Capstone.Capstone.service.ChatMessageService;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class ChatMessageServiceImpl implements ChatMessageService {
    private final ChatRoomRepository chatRoomRepository;
    private final ChatMessageRepository chatMessageRepository;
    private final UserService userService;
    @Autowired
    public ChatMessageServiceImpl(ChatRoomRepository chatRoomRepository, ChatMessageRepository chatMessageRepository, UserService userService) {
        this.chatRoomRepository = chatRoomRepository;
        this.chatMessageRepository = chatMessageRepository;
        this.userService = userService;
    }



    @Override
    public ChatMessage createChat(ChatMessage chatMessage) {

        return chatMessageRepository.save(chatMessage);

    }

    @Override
    public ChatMessage convertToEntity(ChatMessageDto chatMessageDto) {
        ChatMessage chatMessage=new ChatMessage();
        Optional<ChatRoom> OptionalChatRoom=chatRoomRepository.findById(chatMessageDto.getRoomId());
        if(OptionalChatRoom.isPresent())
        {
            ChatRoom chatRoom=OptionalChatRoom.get();
            chatMessage.setChatRoom(chatRoom);

        }
        chatMessage.setUser(userService.convertToEntity(chatMessageDto.getUserDto()));
        chatMessage.setId(chatMessageDto.getId());
        log.info("setMessage={}",chatMessageDto.getMessage());
        chatMessage.setMessage(chatMessageDto.getMessage());
        chatMessage.setTimestamp(chatMessageDto.getTimestamp());

        return chatMessage;
    }
    @Override
    public ChatMessageDto convertToDto(ChatMessage chatMessage){
    ChatMessageDto chatMessageDto=new ChatMessageDto();
    chatMessageDto.setUserDto(userService.convertToDto(chatMessage.getUser()));
    chatMessageDto.setMessage(chatMessage.getMessage());
    chatMessageDto.setRoomId(chatMessage.getChatRoom().getId());
    chatMessageDto.setTimestamp(chatMessage.getTimestamp());
    return  chatMessageDto;

    }


    @Override
    public List<ChatMessage> getMessagesByRoomId(Long roomId) {
        return chatMessageRepository.findByChatRoomId(roomId);
    }

}



