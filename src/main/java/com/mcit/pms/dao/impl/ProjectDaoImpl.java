package com.mcit.pms.dao.impl;

import com.mcit.pms.dao.ProjectDao;
import com.mcit.pms.model.Project;
import com.mcit.pms.model.ProjectMember;
import com.mcit.pms.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Repository
public class ProjectDaoImpl extends JdbcDaoSupport implements ProjectDao {

    @Autowired
    DataSource dataSource;

    @PostConstruct
    private void initialize(){
        setDataSource(dataSource);
    }

    @Override
    public void createProject(Project project) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String sql = "INSERT INTO projects " +
                "(title,description,startdate,enddate,createdBy) VALUES (?, ?,?,?,?)" ;
        getJdbcTemplate().update(sql, new Object[]{
                project.getTitle(),project.getDescription(), project.getStartDate(),
                project.getEndDate(),authentication.getName().toString()
        });
    }

    @Override
    public List<Project> getAllProjects() {
        String sql = "SELECT * from projects";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql);

        List<Project> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            Project project = new Project();
            project.setId((Integer)row.get("pid"));
            project.setTitle((String)row.get("title"));
            project.setDescription((String)row.get("description"));
            project.setStartDate((String) row.get("startdate"));
            project.setEndDate((String)row.get("enddate"));
            result.add(project);
        }

        return result;
    }

    @Override
    public void updateProject(Project project) {
        getJdbcTemplate().execute("UPDATE projects set title = '"+project.getTitle()+"', description = '"+project.getDescription()+"',startdate = '"+project.getStartDate()+"', enddate = '"+project.getEndDate()+"' where pid = "+ project.getId());
    }

    @Override
    public void setProjectMember(Integer id, Integer projectId) {
        String sql = "INSERT INTO projectmember " +
                "(projectid,member) VALUES (?, ?)" ;
        getJdbcTemplate().update(sql, new Object[]{
                projectId,id
        });
    }

    @Override
    public List<ProjectMember> getAddedMember(Integer id, Integer projectID) {
        String sql = "SELECT * from projectmember where projectid = ? and member=?";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql, projectID, id);

        List<ProjectMember> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            ProjectMember project = new ProjectMember();
            project.setProjectID((Integer)row.get("projectid"));
            project.setUserID((Integer) row.get("member"));
            result.add(project);
        }

        return result;
    }

    @Override
    public Project getById(Integer id) {
        String sql = "SELECT * FROM projects WHERE pid = ?";
        return (Project) getJdbcTemplate().queryForObject(sql, new Object[]{id}, new RowMapper<Project>(){
            @Override
            public Project mapRow(ResultSet rs, int rwNumber) throws SQLException {
                Project project = new Project();
                project.setId(rs.getInt("pid"));
                project.setTitle(rs.getString("title"));
                project.setDescription(rs.getString("description"));
                project.setStartDate(rs.getString("startdate"));
                project.setEndDate(rs.getString("enddate"));
                return project;
            }
        });
    }

    @Override
    public void deleteProject(Integer id) {
        getJdbcTemplate().execute("DELETE FROM projects WHERE pid = "+ id);
    }

    @Override
    public void deleteProjectMember(Integer userID, Integer projectId) {
        getJdbcTemplate().execute("DELETE FROM projectmember WHERE member = "+userID+" and projectid="+ projectId);
    }

    @Override
    public List<Project> getSessionProjects(Integer id) {
        String sql = "SELECT * FROM projects p inner join projectmember pm on p.pid = pm.projectid where pm.member = ?";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql, id);

        List<Project> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            Project project = new Project();
            project.setId((Integer)row.get("pid"));
            project.setTitle((String)row.get("title"));
            project.setDescription((String)row.get("description"));
            project.setStartDate((String) row.get("startdate"));
            project.setEndDate((String)row.get("enddate"));
            result.add(project);
        }

        return result;
    }
}
