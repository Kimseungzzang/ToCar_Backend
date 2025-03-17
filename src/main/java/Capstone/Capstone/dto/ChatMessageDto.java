package Capstone.Capstone.dto;

import Capstone.Capstone.entity.ChatMessage;
import Capstone.Capstone.entity.ChatRoom;
import Capstone.Capstone.entity.User;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@NoArgsConstructor
@Getter
@Setter
public class ChatMessageDto {

    private Long id;
    private Long roomId;
    private UserDto userDto;
    private String message;
    private String timestamp;

    // 생성자
    public ChatMessageDto(ChatMessage chatMessage) {
        this.id= chatMessage.getId();
        this.roomId=new ChatRoomDto(chatMessage.getChatRoom()).getId();
        this.userDto= UserDto.convertToDto(chatMessage.getUser());



    }




}
