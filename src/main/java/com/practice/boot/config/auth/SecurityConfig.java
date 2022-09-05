package com.practice.boot.config.auth;

import com.practice.boot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().disable()     // h2-console 화면을 사용하기 위해 해당 옵션들 disable
                .and()
                    .authorizeRequests()    // URL별 권한 관리를 설정하는 옵션의 시작점. authorizeRequests가 선언되어야만 anyMachers 옵션 사용 가능
                                            // antMachers : 권한 관리 대상 지정하는 옵션. URL, HTTP 메소드별로 관리 가능
                    .antMatchers("/", "/css/**", "images/**", "/js/**", "/h2-console/**", "/profile").permitAll()
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                    .anyRequest().authenticated()   // 설정된 값 이외 나머지 URL은 모두 인증된 사용자만 허용(로그인한 사용자)
                .and()
                    .logout()   // 로그아웃 기능에 대한 여러 설정의 진입점.
                        .logoutSuccessUrl("/")  // 로그아웃 성공시 / 주소로 이동
                .and()
                    .oauth2Login()  // OAuth2 로그인 기능에 대한 여러 설정의 진입점
                        .userInfoEndpoint() // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정 담당
                            .userService(customOAuth2UserService);  // 소셜 로그인 성공 시 후속조치를 진행할 UserService 인터페이스 구현체 등록, 리소스 서버(소셜 서비스)에서 사용자 정보를 가져온 상태에서 추가로 진행하고자 하는 기능 명시할 수 있음
    }

}
