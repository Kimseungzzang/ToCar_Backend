package Capstone.Capstone.servicelmpl;


import Capstone.Capstone.dto.LikeDto;
import Capstone.Capstone.entity.Community;
import Capstone.Capstone.entity.Like;
import Capstone.Capstone.repository.CommunityRepository;


import Capstone.Capstone.service.CommunityService;

import Capstone.Capstone.repository.LikeRepository;
import Capstone.Capstone.repository.UserRepository;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class CommunityServiceLmpl implements CommunityService {

    private final CommunityRepository communityRepository;
    private final LikeRepository likeRepository;

    private final UserRepository userRepository;



    @Autowired
    public CommunityServiceLmpl(CommunityRepository communityRepository, LikeRepository likeRepository, UserRepository userRepository) {
        this.communityRepository = communityRepository;
        this.likeRepository = likeRepository;
        this.userRepository = userRepository;
    }

    @Override
    public List<Community> findAll() {
        return communityRepository. findAllByOrderByIdDesc();
    }

    @Override
    public Community findById(Long id) {

        Optional<Community> OptionalCommunity=communityRepository.findById(id);
        if (OptionalCommunity.isPresent())
        {
            Community community=OptionalCommunity.get();
            return community;
        }
        return null;
    }


    @Override
    public List<Community> findByTitle(String title) {
        return communityRepository.findByTitleContaining(title);
    }

    @Override
    public Community save(Community community) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime nineHoursLater = now.plusHours(9);

        community.setTime(nineHoursLater);
        community.setLikeCount(0L);
        log.info("community={}",community.getId());
        return communityRepository.save(community);
    }

    @Override
    public Community saveImage(Community community) {
        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String fileName = "image_" + timeStamp + ".jpg"; // 파일 확장자에 맞게 변경

        // 이미지 데이터(dataURL) 추출
        String imageData = community.getImage();

        // dataURL에서 실제 데이터 부분만 분리 (콤마 이후의 부분)
        String base64Image = imageData.split(",")[1];

        // base64로 인코딩된 데이터를 디코딩하여 바이너리 데이터로 변환
        byte[] imageBytes = Base64.getDecoder().decode(base64Image);
        String imageurl="/home/ubuntu/images/"+fileName;
        community.setImage(imageurl);
        // 저장할 파일 경로 지정
        File outputFile = new File(imageurl);

        try (OutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(imageBytes);
        }

        catch (Exception e) {
            e.printStackTrace();

        }
        return community;
    }

    @Override
    public Community update(Long id, Community community) {
        Optional<Community> optionalCommunity = communityRepository.findById(id);
        if (optionalCommunity.isPresent()) {
            Community existingCommunity = optionalCommunity.get();
            existingCommunity.setTitle(community.getTitle());
            existingCommunity.setContent(community.getContent());
            existingCommunity.setNickName(community.getNickName());
            existingCommunity.setTime(community.getTime());
            return communityRepository.save(existingCommunity);
        } else {
            return null; // 또는 적절한 예외 처리
        }
    }

    @Override
    public void delete(long id) {

        communityRepository.deleteById(id);
    }
    @Override
    public void addLike(long communityId,String userId){
       Optional<Community> findCommunity=communityRepository.findById(communityId);
       if(findCommunity.isPresent())
       {
           long LikeCount=findCommunity.get().getLikeCount();
           findCommunity.get().setLikeCount(LikeCount+1);
           communityRepository.save(findCommunity.get());
           List<Like> likeList=likeRepository.findByCommunityIdAndUserId(communityId,userId);

            if (!likeList.isEmpty())
            {
                likeList.get(0).setLiked(true);
                log.info("like={}",likeList.get(0).isLiked());
                likeRepository.save(likeList.get(0));
            }
            else
            {
                LikeDto likeDto=new LikeDto();
                likeDto.setUserId(userId);
                likeDto.setCommunityId(communityId);
                likeDto.setUserId(userId);
                likeDto.setLiked(true);
                Like like=new Like();
                like.setUser(userRepository.findById(userId).get());
                like.setCommunity(communityRepository.findById(communityId).get());
                log.info("likeDto={}",likeDto.isLiked());
                like.setLiked(likeDto.isLiked());
                likeRepository.save(like);
            }

       }
    }


    @Override
    public void subLike(long communityId,String userId){
        Optional<Community> findCommunity=communityRepository.findById(communityId);
        if(findCommunity.isPresent())
        {
            long LikeCount=findCommunity.get().getLikeCount();
            findCommunity.get().setLikeCount(LikeCount-1);
            communityRepository.save(findCommunity.get());
            List<Like> likeList=likeRepository.findByCommunityIdAndUserId(communityId,userId);
            if (!likeList.isEmpty())
            {
                likeList.get(0).setLiked(false);
                log.info("like={}",likeList.get(0).isLiked());
                likeRepository.save(likeList.get(0));
            }
            else
            {
                LikeDto likeDto=new LikeDto();
                likeDto.setUserId(userId);
                likeDto.setCommunityId(communityId);
                likeDto.setUserId(userId);
                likeDto.setLiked(false);
                Like like=new Like();
                like.setUser(userRepository.findById(userId).get());
                like.setCommunity(communityRepository.findById(communityId).get());
                log.info("likeDto={}",likeDto.isLiked());
                like.setLiked(likeDto.isLiked());
                likeRepository.save(like);
            }

        }
    }
    @Override
    public List<Community> findPopularCommunity() {
        return communityRepository.findTop5ByOrderByLikeCountDesc();
    }

    @Override
    public void addClickCount(Long id) {
        Optional<Community> community= communityRepository.findById(id);
        if(community.isPresent())
        {
          Community ClickCommunity=community.get();
           long presentCount= ClickCommunity.getClickCount();
           log.info("{}",presentCount);
           presentCount++;
            ClickCommunity.setClickCount(presentCount);
            log.info("{}",presentCount);
            log.info("{},{}",ClickCommunity.getClickCount());
            communityRepository.save(ClickCommunity);

        }
    }






}

