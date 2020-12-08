package com.mcit.pms.dao;

import com.mcit.pms.model.Project;
import com.mcit.pms.model.ProjectMember;

import java.util.List;

public interface ProjectDao {
    void createProject(Project project);

    List<Project> getAllProjects();

    void updateProject(Project project);

    void setProjectMember(Integer id, Integer projectId);

    List<ProjectMember> getAddedMember(Integer id, Integer projectID);

    Project getById(Integer id);

    void deleteProject(Integer id);

    void deleteProjectMember(Integer userID, Integer projectId);

    List<Project> getSessionProjects(Integer id);
}
