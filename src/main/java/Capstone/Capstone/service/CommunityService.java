
package Capstone.Capstone.service;
import Capstone.Capstone.entity.Community;

import java.util.List;


public interface CommunityService {
    List<Community> findAll();
    Community findById(Long id);
    List<Community> findByTitle(String title);

    Community save(Community community);
    Community update(Long id, Community community);

    Community saveImage(Community community);

    void delete(long id);

    void addLike(long communityId,String userId) ;
    void subLike(long communityId,String userId);

    List<Community> findPopularCommunity();

    void addClickCount(Long id);




}
