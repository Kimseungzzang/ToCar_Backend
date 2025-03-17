package Capstone.Capstone.service;

import Capstone.Capstone.dto.ChatMessageDto;
import Capstone.Capstone.entity.ChatMessage;

import java.util.List;

public interface ChatMessageService {
   ChatMessage createChat(ChatMessage chatMessage);

   ChatMessage convertToEntity(ChatMessageDto chatMessageDto);

   ChatMessageDto convertToDto(ChatMessage chatMessage);

   List<ChatMessage> getMessagesByRoomId(Long roomId);
}
