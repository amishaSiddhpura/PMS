package com.mcit.pms.service;

import com.mcit.pms.model.Project;
import com.mcit.pms.model.ProjectMember;

import java.util.List;

public interface ProjectService {
    void insertProject(Project project);

    List<Project> getAllProjects();

    void updateProject(Project project);

    void setProjectMember(Integer id, Integer projectId);

    List<ProjectMember> getAddedMember(Integer id, Integer ProjectId);

    Project getById(Integer id);

    void deleteProject(Integer id);

    void deleteProjectMember(Integer id, Integer projectId);

    List<Project> getSessionProjects(Integer id);
}
