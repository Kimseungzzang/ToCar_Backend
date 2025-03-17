package Capstone.Capstone.controller;


import Capstone.Capstone.dto.CommentDto;
import Capstone.Capstone.dto.CommunityDto;
import Capstone.Capstone.dto.LikeDto;
import Capstone.Capstone.entity.Community;
import Capstone.Capstone.service.CommentService;
import Capstone.Capstone.service.CommunityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.modelmapper.ModelMapper;

import java.io.IOException;
import java.util.List;

import static java.util.Arrays.stream;

@Slf4j
@RestController
@RequestMapping("/api/community")
@Tag(name="Community API",description = "Community API입니다.")
public class CommunityController {

    private final CommunityService communityService;
    private final CommentService commentService;
    private final ModelMapper modelMapper;

    @Autowired
    public CommunityController(CommunityService communityService, CommentService commentService, ModelMapper modelMapper) {
        this.communityService = communityService;
        this.commentService = commentService;

        this.modelMapper = modelMapper;
    }

    @GetMapping("/")
    @Tag(name="Community API")
    @Operation(summary = "모든 글 찾기",description = "모든 글을 찾아옵니다.")
    public ResponseEntity<List<CommunityDto>> getAllCommunities() {
        List<Community> communities = communityService.findAll();
       List<CommunityDto>communityDtos=communities.stream()
                .map(
                        community -> modelMapper.map(community, CommunityDto.class)
                )
                .toList();
        communityDtos.forEach(community -> {
            community.setCommentSum(commentService.allCommentById(community.getId()));
        });


        return new ResponseEntity<>(communityDtos, HttpStatus.OK);
    }

    @GetMapping("/post/{id}")
    @Tag(name="Community API")
    public  ResponseEntity<CommunityDto> getCommunityPost(@PathVariable Long id){
        CommunityDto communityDto=new CommunityDto();
       communityDto= modelMapper.map(communityService.findById(id), CommunityDto.class);
        return new ResponseEntity<>(communityDto,HttpStatus.OK);
    }

    @PostMapping("/save")
    @Tag(name="Community API")
    @Operation(summary = "글 생성",description = "글을 생성하여 저장합니다.")
    public ResponseEntity<String> createCommunity(@RequestBody Community community, @CookieValue(value = "JSESSIONID", defaultValue = "") String sessionId, HttpServletRequest request) throws IOException {

        HttpSession session = request.getSession(false);
        if (session != null && sessionId.equals(session.getId())) {
            String nickName = (String) session.getAttribute("nickname");
            log.info("id={}",nickName);
            community.setNickName(nickName);
            log.info("nickName={}",community.getNickName());
        } else {
            return new ResponseEntity<>("로그아웃 상태입니다.",HttpStatus.BAD_REQUEST);

        }
        if (community.getImage()!=null) {
            communityService.saveImage(community);
        }
        communityService.save(community);
            return new ResponseEntity<>( "굿", HttpStatus.CREATED);


    }

    @PutMapping("/{id}")
    @Tag(name="Community API")
    @Operation(summary = "글 수정",description = "게시판 글을 수정합니다.")
    public Community updateCommunity(@PathVariable Long id, @RequestBody Community community) {

        return communityService.update(id, community);
    }

    @DeleteMapping("/{id}")
    @Tag(name="Community API")
    @Operation(summary = "글 삭제",description = "게시판 글을 삭제합니다.")
    public ResponseEntity<String> deleteCommunity(@PathVariable Long id,HttpServletRequest request) {
        HttpSession session = request.getSession(false);
         Community community=communityService.findById(id);
        log.info("community={}",community);

            String findTitle=community.getTitle();
            String findNickName = community.getNickName();
            log.info("findTitle={} findNickName={}",findTitle,findNickName);
            String nickName = (String) session.getAttribute("nickname");
            log.info("nickName={}",nickName);
                if (findNickName.equals(nickName)) {
                    communityService.delete(id);
                    return new ResponseEntity<>("삭제 성공",HttpStatus.OK);

                }

        return new ResponseEntity<>("삭제 실패",HttpStatus.BAD_REQUEST);
    }
    @PutMapping("/addLike/{id}")
    @Tag(name="Community API")
    @Operation(summary="좋아요 추가",description="게시판 글 좋아요 개수를 1개 늘립니다.")
    public ResponseEntity<String> addLike(@PathVariable Long id,@CookieValue(value = "id", defaultValue = "") String sessionId ){
        communityService.addLike(id,sessionId);
        return new ResponseEntity<>("좋아요 성공",HttpStatus.OK);

    }


    @PutMapping("/subLike/{id}")
    @Tag(name="Community API")
    @Operation(summary="좋아요 감소",description="게시판 글 좋아요 개수를 1개 줄입니다..")
    public ResponseEntity<String> subLike(@PathVariable Long id,@CookieValue(value = "id", defaultValue = "") String sessionId){
        communityService.subLike(id,sessionId);
        return new ResponseEntity<>("좋아요 해제 성공",HttpStatus.OK);

    }
    @PutMapping("/addClickCount")
    public ResponseEntity<String> addClickCount(@RequestBody CommunityDto communityDto){
        Long id=communityDto.getId();
        communityService.addClickCount(id);
        return  new ResponseEntity<>("조회완료",HttpStatus.OK);
    }

    @Tag(name="Community API")
    @Operation(summary="인기글 조회",description="게시판 글 좋아요 개수가 많은 게시글부터 5개 조회합니다.")
    @GetMapping("/PopularCommunity")
    public ResponseEntity<List<CommunityDto>> getPopularCommunity(){
        List<CommunityDto> popularCommunity= communityService.findPopularCommunity().stream()
                .map(community -> modelMapper.map(community, CommunityDto.class))
                .toList();



        return new ResponseEntity<>(popularCommunity,HttpStatus.OK);
    }
    @Tag(name="Community API")
    @GetMapping("/search")
    public ResponseEntity<List<CommunityDto>> getCommunityByTitle(@RequestParam String title){
        List<CommunityDto> communityDto=communityService.findByTitle(title).stream().map(
                community -> modelMapper.map(community,CommunityDto.class)).toList();


        return new ResponseEntity<>(communityDto,HttpStatus.OK);
    }
    @Tag(name="Community API")
    @Operation(summary="댓글 포함 조회")
    @GetMapping("/posts/read/{id}")
    public  ResponseEntity <CommunityDto> read(@PathVariable Long id) {
        Community community=communityService.findById(id);
        CommunityDto communityDto = modelMapper.map( community,CommunityDto.class);
         List<CommentDto> commentsDto=community.getComments().stream()
                .map(comment -> modelMapper.map(comment, CommentDto.class))
                .toList();
         List<LikeDto> likesDto=community.getLikes().stream()
                 .map(like -> modelMapper.map(like,LikeDto.class))
                         .toList();
         communityDto.setLikesDto(likesDto);
         communityDto.setCommentsDto(commentsDto);





                return new ResponseEntity<>(communityDto, HttpStatus.OK);
            }
    }



