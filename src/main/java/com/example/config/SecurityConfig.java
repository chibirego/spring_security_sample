package com.example.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.context.annotation.Bean;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// 認可の設定
		http.authorizeRequests()
			.antMatchers("/loginForm").permitAll()
			.anyRequest().authenticated();
	
		http.formLogin()
			.loginProcessingUrl("/login")
			.loginPage("/loginForm")
			.usernameParameter("email")
			.passwordParameter("password")
			.defaultSuccessUrl("/home", true)
			.failureUrl("/loginForm?error");
		
		// ログアウトの処理
		http.logout()
			.logoutUrl("/logout")
			.logoutSuccessUrl("/loginForm");
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
	}
}
