package Capstone.Capstone.repository;

import Capstone.Capstone.entity.ChatRoom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ChatRoomRepository extends JpaRepository<ChatRoom,Long> {
    @Query("SELECT cr.id FROM ChatRoom cr " +
            "JOIN cr.users u " +
            "WHERE u.nickname IN :userIds " +
            "GROUP BY cr.id " +
            "HAVING COUNT(DISTINCT u.nickname) = :userCount")
    List<Long> findChatRoomIdByUserIds(List<String> userIds, int userCount);

    @Query("SELECT cr.id FROM ChatRoom cr " +
            "JOIN cr.users u " +
            "WHERE u.id = :userId")
    List<Long> findChatRoomIdsByUserId( String userId);

    @Query("SELECT u.nickname FROM User u " +
            "JOIN u.chatRooms cr " +
            "WHERE cr.id = :chatRoomId AND u.id <> :userId")
    List<String> findOtherUserIdsInChatRoom(Long chatRoomId, String userId);
}
