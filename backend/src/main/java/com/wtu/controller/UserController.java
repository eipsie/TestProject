package com.wtu.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wtu.annotation.RequireRole;
import com.wtu.dto.LoginDTO;
import com.wtu.dto.RegisterDTO;
import com.wtu.dto.UserDTO;
import com.wtu.result.Result;
import com.wtu.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "用户管理", description = "用户管理相关接口")
public class UserController {

    @Autowired
    private UserService userService;
    
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping("/auth/login")
    @Operation(summary = "用户登录")
    public Result<UserDTO> login(@RequestBody LoginDTO loginDTO, HttpServletRequest request) {
        Result<UserDTO> result = userService.login(loginDTO);
        if (result.getCode() == 1) {
            try {
                // 登录成功，将用户信息转为JSON字符串存入session
                HttpSession session = request.getSession();
                String userJson = objectMapper.writeValueAsString(result.getData());
                session.setAttribute("user", userJson);
            } catch (JsonProcessingException e) {
                return Result.error("登录过程中出现错误");
            }
        }
        return result;
    }

    @PostMapping("/auth/register")
    @Operation(summary = "用户注册")
    public Result<UserDTO> register(@RequestBody RegisterDTO registerDTO) {
        return userService.register(registerDTO);
    }

    @GetMapping("/users")
    @Operation(summary = "获取用户列表")
    @RequireRole({"admin", "manager"})
    public Result<List<UserDTO>> getAllUsers() {
        return userService.getAllUsers();
    }

    @GetMapping("/users/{id}")
    @Operation(summary = "获取用户详情")
    public Result<UserDTO> getUserById(@PathVariable Long id, HttpServletRequest request) {
        // 获取当前登录用户
        UserDTO currentUser = getCurrentUser(request);
        if (currentUser == null) {
            return Result.error("用户未登录");
        }
        
        // 检查权限
        if ("admin".equals(currentUser.getRole())) {
            // 管理员可以查看任何用户
            return userService.getUserById(id);
        } else if ("manager".equals(currentUser.getRole())) {
            // 项目经理可以查看自己和普通用户
            Result<UserDTO> result = userService.getUserById(id);
            if (result.getCode() == 1) {
                UserDTO targetUser = result.getData();
                if (id.equals(currentUser.getId()) || "user".equals(targetUser.getRole())) {
                    return result;
                }
                return Result.error("没有权限查看该用户");
            }
            return result;
        } else {
            // 普通用户只能查看自己
            if (id.equals(currentUser.getId())) {
                return userService.getUserById(id);
            }
            return Result.error("没有权限查看该用户");
        }
    }

    @PutMapping("/users/{id}")
    @Operation(summary = "更新用户信息")
    public Result<UserDTO> updateUser(@PathVariable Long id, @RequestBody UserDTO userDTO, HttpServletRequest request) {
        // 获取当前登录用户
        UserDTO currentUser = getCurrentUser(request);
        if (currentUser == null) {
            return Result.error("用户未登录");
        }
        
        // 检查权限
        if ("admin".equals(currentUser.getRole())) {
            // 管理员可以更新任何用户
            // 防止修改用户角色为admin
            if (!"admin".equals(currentUser.getId().toString()) && "admin".equals(userDTO.getRole())) {
                return Result.error("不能将用户角色修改为管理员");
            }
            return userService.updateUser(id, userDTO);
        } else if ("manager".equals(currentUser.getRole())) {
            // 项目经理可以更新自己和普通用户
            Result<UserDTO> result = userService.getUserById(id);
            if (result.getCode() == 1) {
                UserDTO targetUser = result.getData();
                if (id.equals(currentUser.getId()) || "user".equals(targetUser.getRole())) {
                    // 项目经理不能修改用户角色为manager或admin
                    if ("manager".equals(userDTO.getRole()) || "admin".equals(userDTO.getRole())) {
                        return Result.error("没有权限修改为该角色");
                    }
                    return userService.updateUser(id, userDTO);
                }
                return Result.error("没有权限更新该用户");
            }
            return result;
        } else {
            // 普通用户只能更新自己，且不能修改角色
            if (id.equals(currentUser.getId())) {
                // 不允许修改角色
                userDTO.setRole(currentUser.getRole());
                return userService.updateUser(id, userDTO);
            }
            return Result.error("没有权限更新该用户");
        }
    }
    
    /**
     * 获取当前登录用户
     */
    private UserDTO getCurrentUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        
        try {
            String userJson = (String) session.getAttribute("user");
            if (userJson == null) {
                return null;
            }
            return objectMapper.readValue(userJson, UserDTO.class);
        } catch (Exception e) {
            return null;
        }
    }
} 