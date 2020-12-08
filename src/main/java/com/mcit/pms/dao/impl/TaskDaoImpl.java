package com.mcit.pms.dao.impl;

import com.mcit.pms.dao.TaskDao;
import com.mcit.pms.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Repository
public class TaskDaoImpl extends JdbcDaoSupport implements TaskDao {

    @Autowired
    DataSource dataSource;

    @PostConstruct
    private void initialize(){
        setDataSource(dataSource);
    }

    @Override
    public void saveTask(Task task) {
        String sql = "INSERT INTO task " +
                "(task, description,deadline,state,userid,projectid) VALUES (?,?,?,?,?,?)" ;
        getJdbcTemplate().update(sql, new Object[]{
                task.getTitle(), task.getDescription(),task.getDeadline(),task.getState(),
                task.getUser(),task.getProject()
        });
    }

    @Override
    public List<Task> showAllTasks() {
        String sql = "SELECT t.id, t.task, t.description, t.deadline, t.state, p.title, p.pid FROM task t inner join projects p on p.pid = t.projectid;";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql);

        List<Task> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            Task task = new Task();
            task.setId((Integer)row.get("id"));
            task.setTitle((String)row.get("task"));
            task.setDescription((String)row.get("description"));
            task.setDeadline((String) row.get("deadline"));
            task.setState((String)row.get("state"));
            task.setProject((String)row.get("title"));
            task.setProjectId((Integer) row.get("pid"));
            result.add(task);
        }

        return result;
    }

    @Override
    public Task findByTaskId(String id) {
        String sql = "SELECT * FROM task t inner join projects p on p.pid = t.projectid where t.id = ?";
        return (Task) getJdbcTemplate().queryForObject(sql, new Object[]{id}, new RowMapper<Task>(){
            @Override
            public Task mapRow(ResultSet rs, int rwNumber) throws SQLException {
                Task task = new Task();
                task.setId(rs.getInt("id"));
                task.setTitle(rs.getString("task"));
                task.setDescription(rs.getString("description"));
                task.setDeadline(rs.getString("deadline"));
                task.setState(rs.getString("state"));
                task.setProject( rs.getString("title"));
                task.setProjectId(rs.getInt("projectid"));
                return task;
            }
        });
    }

    @Override
    public void deleteTask(Integer id) {
        getJdbcTemplate().execute("delete from task where id ="+ id);
    }

    @Override
    public List<Task> getByUserName(String name) {
        String sql = "select t.id,t.task,t.state,t.description from task t inner join users u on u.id = t.userid where u.username = ?";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql,name);

        List<Task> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            Task task = new Task();
            task.setId((Integer)row.get("id"));
            task.setTitle((String)row.get("task"));
            task.setDescription((String)row.get("description"));
            task.setDeadline((String) row.get("deadline"));
            task.setState((String)row.get("state"));
            result.add(task);
        }

        return result;
    }

    @Override
    public Task getById(Integer id) {
        String sql = "SELECT * FROM task WHERE id = ?";
        return (Task) getJdbcTemplate().queryForObject(sql, new Object[]{id}, new RowMapper<Task>(){
            @Override
            public Task mapRow(ResultSet rs, int rwNumber) throws SQLException {
                Task task = new Task();
                task.setId(rs.getInt("id"));
                task.setTitle(rs.getString("task"));
                task.setDescription(rs.getString("description"));
                task.setDeadline(rs.getString("deadline"));
                task.setState(rs.getString("state"));
                return task;
            }
        });
    }

    @Override
    public void updateStatus(Task task) {
        getJdbcTemplate().execute("update task set state = '"+ task.getState() +"' where id = "+ task.getId());
    }

    @Override
    public void updateTask(Task task) {
        getJdbcTemplate().execute("update task set task= '"+task.getTitle()+"',description= '"+task.getDescription()+"', deadline = '"+task.getDeadline()+"', state='"+task.getState()+"',projectid="+ Integer.parseInt(task.getProject())+", userid='"+task.getUser()+"' where id = "+task.getId());

    }
}
