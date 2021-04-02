package com.okta.spring.example.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Controller
public class HomeController {
    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping(value = "/custom-login")
    public ModelAndView getLogin() {
        return new ModelAndView("login");
    }

    @GetMapping("/verify")
    public String getVerify() {
        return "verify";
    }

    @GetMapping("/change-password")
    public String getChangePassword() {
        return "verify";
    }

    @GetMapping("/forgot-password")
    public ModelAndView getForgotPassword() {
        return new ModelAndView("forgotpassword");
    }

    @GetMapping("/register")
    public ModelAndView getRegister() {
        return new ModelAndView("register");
    }

    @GetMapping("/403")
    public String error403() {
        return "403";
    }
}