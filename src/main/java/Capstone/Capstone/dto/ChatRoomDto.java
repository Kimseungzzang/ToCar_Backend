package Capstone.Capstone.dto;


import Capstone.Capstone.entity.ChatRoom;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ChatRoom 데이터 전송 객체(Data Transfer Object).
 */

@Getter
@Setter
public class ChatRoomDto {

    private Long id;
    private List<ChatMessageDto> chatMessages;
    private Set<UserDto> users; //

    // 기본 생성자
    public ChatRoomDto() {
    }

    // 모든 필드를 포함하는 생성자
    public ChatRoomDto(ChatRoom chatRoom) {
        this.id = chatRoom.getId();
        this.chatMessages = chatRoom.getChatMessages().stream()
                .map(chatMessage -> new ChatMessageDto(chatMessage))
                .collect(Collectors.toList());

        this.users = chatRoom.getUsers().stream()
                .map(user ->  UserDto.convertToDto(user))
                .collect(Collectors.toSet());
    }




}
