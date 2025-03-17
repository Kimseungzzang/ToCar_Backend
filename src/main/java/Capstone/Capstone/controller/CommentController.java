package Capstone.Capstone.controller;


import Capstone.Capstone.dto.CommentDto;
import Capstone.Capstone.service.CommentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@Slf4j
@RestController
@RequestMapping("/api/comments")
@Tag(name="Comment", description = "Comment API입니다")
public class CommentController {


    private final CommentService commentService;

    private final ModelMapper modelMapper;

    @Autowired
    CommentController(CommentService commentService, ModelMapper modelMapper){
        this.commentService=commentService;
        this.modelMapper = modelMapper;
    }

    @PostMapping("/save")
    @Tag(name="Community API")
    @Operation(summary = "댓글 쓰기",description = "댓글을 저장해줍니다")
    public ResponseEntity<String> addComment(@RequestBody CommentDto commentDto, @CookieValue(value = "JSESSIONID", defaultValue = "") String sessionId, HttpServletRequest request) {
        log.info("communityId={}",commentDto.getCommunityId());
        HttpSession session = request.getSession(false);
        if (session != null && sessionId.equals(session.getId())) {
            String nickName = (String) session.getAttribute("nickname");
            commentDto.setNickName(nickName);
        } else {
            return new ResponseEntity<>("로그아웃 상태입니다.", HttpStatus.BAD_REQUEST);
        }
        commentService.addComment(commentDto);
        return new ResponseEntity<>("댓글 작성 완료.", HttpStatus.CREATED);

    }

    @GetMapping("/{id}")
    @Tag(name="Community API")
    @Operation(summary = "id로 댓글을 찾습니다",description = "댓글을 찾습니다")
    public ResponseEntity<CommentDto> getCommentById(@PathVariable("id") Long id) {
        CommentDto commentDto = modelMapper.map(commentService.getCommentById(id),CommentDto.class);
        return new ResponseEntity<>(commentDto, HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    @Tag(name="Community API")
    @Operation(summary = "댓글 삭제",description = "댓글 삭제합니다.")
    public ResponseEntity<String> deleteComment(@PathVariable("id") Long id, @CookieValue(value = "JSESSIONID", defaultValue = "") String sessionId, HttpServletRequest request) {


        HttpSession session = request.getSession(false);
        if (session != null && sessionId.equals(session.getId())) {

            String nickName = (String) session.getAttribute("nickName");
            if(nickName.equals( commentService.getCommentById(id).getNickName()))
            {
                commentService.deleteComment(id);
            }
            else
            {
                return new ResponseEntity<>("작성자만 삭제할 수 있습니다.",HttpStatus.BAD_REQUEST);
            }
        } else {
            return new ResponseEntity<>("로그아웃 상태입니다.", HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }



}