<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@ taglib prefix="font" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page session="true"%>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>Add Task</title>
    <style>
        *{ font-family: 'Quicksand', sans-serif;}

        .content-table{
            border-collapse: collapse;
            margin: 25px 0;
            font-size: 0.9em;
            min-width: 400px;
            border-radius: 5px 5px 0 0;
            overflow: hidden;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.15)
        }

        .content-table thead tr{
            background-color: #00a2ff;
            color: white;
            text-align: left;
            font-weight: bold;
        }
        .content-table th, .content-table td{
            padding: 12px 15px;
        }
        .content-table tbody tr{
            border-bottom: 1px solid #dddddd;
        }
        .content-table tbody tr:nth-of-type(even){
            background-color: #f3f3f3;
        }
        .content-table tbody tr:last-of-type{
            border-bottom: 2px solid #00a2ff;
        }
        .button {
            border-radius: 4px;
            background-color: #f4511e;
            border: none;
            color: #FFFFFF;
            text-align: center;
            font-size: 15px;
            padding: 20px;
            width: 100px;
            height: 5px;
            transition: all 0.5s;
            cursor: pointer;
            margin: 5px;
            padding-top: 9px;
            padding-bottom: 25px;
        }
    </style>
</head>
<jsp:include page="menu.jsp" />
<body>
<center>
<c:if test="${task.title ne null}">
                <h1 style="color: red;">Edit Task</h1>
</c:if>
<c:if test="${task.title eq null}">
                <h1 style="color: red;">Add New Task</h1>
</c:if>
<div id="addTask">
    <%--@elvariable id="task" type="com.mcit.pms.model.Task"--%>
    <table class="content-table" style="text-align: center">
    <form:form action="/addTask" method="post"
               modelAttribute="task">
        <form:hidden path="id" value = "${task.id}" name="id" />
        <tr>
            <td><label>Task Title</label></td>
            <td><form:input path="title" value="${task.title}" required="true" /></td>
        </tr>
            <tr>
                <td><label>Description</label></td>
                <td><form:input path="description" value="${task.description}" required="true" /></td>
            </tr>
        <tr>
            <td><label>Deadline</label></td>
            <td><form:input type="date" path="deadline" value="${task.deadline}" required="true" /></td>
        </tr>
        <tr>
            <td><label>State</label></td>
            <td><form:select path="state" selected="${task.id}">
                <font:option value="TO-DO">TO-DO</font:option>
                <font:option value="PENDING">PENDING</font:option>
                <font:option value="TESTING">TESTING</font:option>
                <font:option value="COMPLETED">COMPLETED</font:option>
            </form:select></td>
        </tr>
        <tr>
            <td><label>User</label></td>
            <td><form:select path="user" selected="${task.user}">
                <c:forEach items="${user}" var="category">
                    <form:option selected="${category.id eq selecteduserid ?'selected':''}" value="${category.id}">${category.username}</form:option>
                </c:forEach>
            </form:select></td>
        </tr>
        <tr>
                    <td><label>Project</label></td>
                    <td><form:select path="project" selected="${task.title}">
                        <c:forEach items="${projects}" var="project">
                            <form:option value="${project.id}" selected="${project.id eq selectedprojectid ?'selected':''}">${project.title}</form:option>
                        </c:forEach>
                    </form:select></td>
                </tr>
        <tr>
            <td colspan=2 style="text-align:center;"><c:if test="${task.title eq null}">
                <input type="SUBMIT" class="button" value="Submit" name="SUBMIT" />
            </c:if>
                <c:if test="${task.title ne null}">
                    <input type="SUBMIT" class="button" value="Update" name="SUBMIT" />
                </c:if></td>
        </tr>
        </table>
    </form:form>
</div>
</center>
</body>
</html>
