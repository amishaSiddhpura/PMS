package com.mcit.pms.controllers;

import java.util.*;

import com.mcit.pms.model.*;
import com.mcit.pms.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;

@Controller
public class PMSController {

	@Autowired
	UserService userService;

	@Autowired
	AuthorityService authorityService;

	@Autowired
	ProjectService projectService;

	@Autowired
	TaskService taskService;

	@Autowired
	AuthenticationTrustResolver authenticationTrustResolver;

	@RequestMapping({"/", "/welcome"})
	public ModelAndView firstPage(Model model) {
		try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			model.addAttribute("userRole",authentication.getAuthorities().toString());
			if (isCurrentAuthenticationAnonymous()) {
				return new ModelAndView("login");
			}
			return new ModelAndView("welcome");
		} catch (Exception e){
			e.printStackTrace();
			return new ModelAndView("login");
		}

	}

	private boolean isCurrentAuthenticationAnonymous() {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authenticationTrustResolver.isAnonymous(authentication);
	}

	@RequestMapping("/showUsers")
	public ModelAndView getUsers() {
		List<User> users = userService.getAllUsers();
		ModelAndView model = new ModelAndView("showUsers");
		model.addObject("users", users);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
		return model;
	}

	@RequestMapping(value = "/addUser", method = RequestMethod.GET)
	public ModelAndView addUser(Model model,
								@RequestParam(value = "error_msg",required = false)String em){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addAttribute("userRole",authentication.getAuthorities().toString());
		model.addAttribute("user",new User());
		model.addAttribute("error",em);
		return new ModelAndView("addUser");
	}

	@RequestMapping(value = "/addUser", method = RequestMethod.POST)
	public ModelAndView addUserPost(@ModelAttribute("user") User user,
									@RequestParam("SUBMIT") String submit,
									@RequestParam("id") Integer id) {

		if (submit.equalsIgnoreCase("Submit")){
			//Check if username already exist
			User userExist = userService.findByUserName(user.getUsername());
			if (userExist.getId() != null){
				ModelAndView model = new ModelAndView("redirect:addUser");
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				model.addObject("userRole",authentication.getAuthorities().toString());
				model.addObject("error_msg", "user already exist");
				return model;
			}

			userService.insertUser(user);
			User savedUser = userService.getByUser(user.getUsername());
			authorityService.insertAuthorityOfUser(new Authority(savedUser.getId(),user.getUsername(),user.getRole()));
			List<User> users = userService.getAllUsers();
			ModelAndView model = new ModelAndView("showUsers");
			model.addObject("users", users);
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			model.addObject("userRole",authentication.getAuthorities().toString());
			return model;
		}else{
			userService.updateUser(user);
			authorityService.updateUser(new Authority(user.getId(),user.getUsername(),user.getRole()));
			List<User> users = userService.getAllUsers();
			ModelAndView model = new ModelAndView("showUsers");
			model.addObject("users",users);
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			model.addObject("userRole",authentication.getAuthorities().toString());
			return model;
		}
	}

	@RequestMapping(value = "/editUser", method = RequestMethod.GET)
	public ModelAndView editUser(@RequestParam("username") String username){
		//Map<String,Object> map = new HashMap<>();
		User user = userService.findByUserName(username);
		//map.put("user", user);
		ModelAndView model = new ModelAndView("addUser");
		model.addObject("user",user);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
return model;
		//return new ModelAndView("addUser",map);
	}

	@RequestMapping(value = "/deleteUser", method = RequestMethod.GET)
	public ModelAndView deleteUser(@RequestParam("id") Integer id){
		userService.deleteUser(id);
		return new ModelAndView("redirect:showUsers");
	}


	@RequestMapping(value = "/addNewProject", method = RequestMethod.GET)
	public ModelAndView addProject(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addAttribute("userRole",authentication.getAuthorities().toString());
		model.addAttribute("project", new Project());
		return new ModelAndView("addproject");
	}

	@RequestMapping(value = "/addNewProject", method = RequestMethod.POST)
	public ModelAndView addProjectPost(@ModelAttribute("project") Project project,
									   @RequestParam("SUBMIT") String submit,
									   @RequestParam("id") Integer id) {

		if (submit.equalsIgnoreCase("Submit")){
			//Check if username already exist
			//userService.checkUserName(user.getUsername());

			projectService.insertProject(project);
			List<Project> projects = projectService.getAllProjects();
			ModelAndView model = new ModelAndView("showProjects");
			model.addObject("projects", projects);
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			model.addObject("userRole",authentication.getAuthorities().toString());
			return model;
		}else{
			project.setId(id);
			projectService.updateProject(project);
			List<User> users = userService.getAllUsers();
			ModelAndView model = new ModelAndView("redirect:showProjects");
			model.addObject("users",users);
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			model.addObject("userRole",authentication.getAuthorities().toString());
			return model;
		}
	}

	@RequestMapping(value = "/editProject", method = RequestMethod.GET)
	public ModelAndView editProject(@RequestParam("id") Integer id){
		Map<String,Object> map = new HashMap<>();
		Project project = projectService.getById(id);
		map.put("project", project);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		map.put("userRole",authentication.getAuthorities().toString());
		return new ModelAndView("addproject",map);
	}

	@RequestMapping(value = "/deleteProject", method = RequestMethod.GET)
	public ModelAndView deleteProject(@RequestParam("id") Integer id){
		ModelAndView model = new ModelAndView("redirect:showProjects");
		projectService.deleteProject(id);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
		return model;
	}

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String login(Model model, String error, String logout) {
		if (error != null)
			model.addAttribute("errorMsg", "Your username and password are invalid.");

		if (logout != null)
			model.addAttribute("msg", "You have been logged out successfully.");

		return "login";
	}

	@RequestMapping("/showProjects")
	public ModelAndView getProjects() {

		ModelAndView model = new ModelAndView("showProjects");
		List<Project> projects=projectService.getAllProjects();
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		//System.out.println(authentication.getAuthorities().toString());
		User user = userService.findByUserName(authentication.getName());
		//List<Project> projects = projectService.getProjectByUserId(user.getId());
		if (authentication.getAuthorities().toString().equalsIgnoreCase("[ROLE_ADMIN]") ){
			model.addObject("projects", projects=projectService.getAllProjects());
		}else
		{
			List<Project> projectList = projectService.getSessionProjects(user.getId());
			model.addObject("projects", projectList);
		}
		model.addObject("userRole",authentication.getAuthorities().toString());
		return model;
	}

	@RequestMapping(value = "/assignMembers", method = RequestMethod.GET)
	public ModelAndView assign(@RequestParam("id") Integer id){
		Map<String,Object> map = new HashMap<>();
		List<User> unassignedUsers = new ArrayList<>();
		Project project = projectService.getById(id);
		unassignedUsers.addAll(userService.getunAssignedUsers(id));
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		map.put("userRole",authentication.getAuthorities().toString());
		map.put("users",unassignedUsers);
		map.put("projectId",id);
		map.put("showRemoveMember", 0);
		map.put("projectName", project.getTitle());
		return new ModelAndView("assignMembers",map);
	}

	@RequestMapping(value = "/setMember", method = RequestMethod.GET)
	public ModelAndView setPermission(@RequestParam("id")Integer id,
									  @RequestParam("projectId")Integer projectId){

		Map<String,Object> map = new HashMap<>();
		projectService.setProjectMember(id,projectId);
		List<User> users = userService.getAllUsers();
		List<Integer> list = new ArrayList<>();
		List<ProjectMember> members =  projectService.getAddedMember(id,projectId);
		members.forEach(x ->{
			users.forEach(y->{
				if (y.getId().equals(x.getUserID())){
					List <ProjectMember> project = projectService.getAddedMember(y.getId(),projectId);
					if (project.size() > 0)
					list.add(y.getId());
				}
			});
		});

		map.put("assignedUsers",list);
		List<User> user = new ArrayList<>();
		list.forEach(x->{
			User userToShow = userService.getById(x);
			user.add(userToShow);
		});
		map.put("users",user);
		return new ModelAndView("redirect:showProjects",map);
	}

	@RequestMapping(value = "/removeMember", method = RequestMethod.GET)
	public ModelAndView deleteMember(@RequestParam("id")Integer id,
									  @RequestParam("projectId")Integer projectId){

		Map<String,Object> map = new HashMap<>();
		projectService.deleteProjectMember(id,projectId);

		return new ModelAndView("redirect:showProjects",map);
	}

	@RequestMapping(value = "/showMembers", method = RequestMethod.GET)
	public ModelAndView showassign(@RequestParam("projectId") Integer id){
		Map<String,Object> map = new HashMap<>();
		List<User> users = userService.getAllUsers();
		List<User> assignedUsers = new ArrayList<>();
		assignedUsers.addAll(userService.getAssignedUsers(id));

		map.put("users",assignedUsers);
		map.put("projectId",id);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		map.put("userRole",authentication.getAuthorities().toString());
		map.put("showRemoveMember", 1);
		return new ModelAndView("assignMembers",map);
	}

	@RequestMapping(value = "/addTask", method = RequestMethod.GET)
	public ModelAndView addTask(Model model){
		model.addAttribute("task",new Task());
		List<User> s = userService.getMembers();
		model.addAttribute("user",s);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addAttribute("userRole",authentication.getAuthorities().toString());
		model.addAttribute("projects",projectService.getAllProjects());
		return new ModelAndView("addTask");
	}

	@RequestMapping(value = "/addTask", method = RequestMethod.POST)
	public ModelAndView addTaskPost(@ModelAttribute("task") Task task,
									@RequestParam("SUBMIT") String submit,
									@RequestParam("id") Integer id) {

			if (submit.equalsIgnoreCase("SUBMIT")){
				ModelAndView model = new ModelAndView("redirect:showTasks");
				List<User> userList = userService.getAllUsers();
				taskService.saveTask(task);
				model.addObject("task",task);
				model.addObject("user",userList);
				return model;
			}else{
				//task.setId(id);
				ModelAndView model = new ModelAndView("redirect:showTasks");
				List<User> userList = userService.getAllUsers();
				taskService.updateTask(task);
				model.addObject("task",task);
				model.addObject("user",userList);
				return model;
			}

		}

	@RequestMapping(value = "/showTasks", method = RequestMethod.GET)
	public ModelAndView showTask(){
		List<Task> taskList = taskService.showAllTasks();
		List<User> userList = userService.getAllUsers();
		ModelAndView model = new ModelAndView("showTasks");
		model.addObject("task",taskList);
		model.addObject("user",userList);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
		return model;
	}

	@RequestMapping(value = "/editTask", method = RequestMethod.GET)
	public ModelAndView editTask(@RequestParam("id") String id){
		Map<String,Object> map = new HashMap<>();
		Task task = taskService.findByTaskId(id);
		map.put("task", task);
		map.put("selecteduserid",task.getUser()) ;
		map.put("selectedprojectid",task.getProjectId());
		map.put("projects",projectService.getAllProjects());
		map.put("user",userService.getMembers());
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		map.put("userRole",authentication.getAuthorities().toString());
		return new ModelAndView("addTask",map);
	}

	@RequestMapping(value = "/deleteTask", method = RequestMethod.GET)
	public ModelAndView deleteTask(@RequestParam("id") Integer id){
		taskService.deleteTask(id);
		return new ModelAndView("redirect:showTasks");
	}

	@RequestMapping(value = "/myTask", method = RequestMethod.GET)
	public ModelAndView myTask(){
		ModelAndView model = new ModelAndView("memberStatistics");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
		User user = userService.findByUserName(authentication.getName());
		model.addObject("user",user);
			List<Task> myTasks = taskService.getByUserName(authentication.getName());
			model.addObject("tasks",myTasks);

			return model;
	}

	@RequestMapping(value = "/changeStatus", method = RequestMethod.GET)
	public ModelAndView changeStatus(@RequestParam("id")Integer id){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		ModelAndView model = new ModelAndView("changeTaskStatus");
		model.addObject("userRole",authentication.getAuthorities().toString());
		Task myTasks = taskService.getById(id);
		model.addObject("tasks",myTasks);
		model.addObject("id",myTasks.getId());
		model.addObject("task", new Task());
		return model;
	}

	@RequestMapping(value = "/updateStatus", method = RequestMethod.POST)
	public ModelAndView updateStatus(@ModelAttribute("task")Task task){
		taskService.updateStatus(task);
		Map<String, Object> map = new HashMap<>();
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		map.put("userRole",authentication.getAuthorities().toString());
		map.put("task", new Task());
		return new ModelAndView("redirect:myTask",map);	}

	@RequestMapping(value = "/memberStat", method = RequestMethod.GET)
	public ModelAndView memberStat(){
		ModelAndView model = new ModelAndView("showMembers");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
		List<User> userList = userService.getMembers();
		model.addObject("user",userList);
		List<Task> myTasks = taskService.getByUserName(authentication.getName());
		model.addObject("showMembers",myTasks);

		return model;
	}

	@RequestMapping(value = "/memberTask", method = RequestMethod.GET)
	public ModelAndView memberTask(@Valid @RequestParam("id") Integer id,
								   @Valid @RequestParam("username") String username){
		ModelAndView model = new ModelAndView("memberStatistics");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		model.addObject("userRole",authentication.getAuthorities().toString());
		User user = userService.getById(id);
		model.addObject("user",user);
		List<Task> myTasks = taskService.getByUserName(username);
		model.addObject("tasks",myTasks);

		return model;
	}

	@RequestMapping("/listMember")
	public ModelAndView listMember() {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		User user = userService.findByUserName(authentication.getName());

		List<Project> projects = projectService.getSessionProjects(user.getId());

		ModelAndView model = new ModelAndView("showProjectwisemember");
		model.addObject("projects", projects);
		model.addObject("userRole",authentication.getAuthorities().toString());
		return model;
	}

}
