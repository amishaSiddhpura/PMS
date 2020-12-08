package com.mcit.pms.service.impl;

import com.mcit.pms.dao.ProjectDao;
import com.mcit.pms.model.Project;
import com.mcit.pms.model.ProjectMember;
import com.mcit.pms.service.ProjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional
@Service
public class ProjectServiceImpl implements ProjectService {

    @Autowired
    ProjectDao projectDao;

    @Override
    public void insertProject(Project project) {
        projectDao.createProject(project);
    }

    @Override
    public List<Project> getAllProjects() {
        return projectDao.getAllProjects();
    }

    @Override
    public void updateProject(Project project) {
        projectDao.updateProject(project);
    }

    @Override
    public void setProjectMember(Integer id, Integer projectId) {
        projectDao.setProjectMember(id,projectId);
    }

    @Override
    public List<ProjectMember> getAddedMember(Integer id, Integer projectID) {
        return projectDao.getAddedMember(id,projectID);
    }

    @Override
    public Project getById(Integer id) {
        return projectDao.getById(id);
    }

    @Override
    public void deleteProject(Integer id) {
        projectDao.deleteProject(id);
    }

    @Override
    public void deleteProjectMember(Integer userID, Integer projectId) {
        projectDao.deleteProjectMember(userID,projectId);
    }

    @Override
    public List<Project> getSessionProjects(Integer id) {
        return projectDao.getSessionProjects(id);
    }


}
