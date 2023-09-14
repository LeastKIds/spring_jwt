package com.example.jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCS8qEOxD59M74fIQROH2YoJ1uPn8AmU8zWdsSCxj4byaO0z80RA18UCypLHmkZNjR5HyFS3M9LKUEQMR8P3clc7tSz1YTbmNACcxU3XR2e5dOeW/MvptgJMlWpDP5OZ7FfF8SPBlwlp7tSLMWjVUzkHAexdp6vn6tMe28zvn0B9eb51K+T18sRZfMLdWx0sRJrBB/7fK2dZRTUDgapKVcmc3sTxAm4dQMmnkwr9ttAUCX6Zpa5pP5j+Rm6ujEEADAczg4t87GpTnckbU6blEJlIcrqnUGWlbdoq9NZR+XWbeH8lgT8sRaTZcmy4O5IFHYT2tvSyFTNMncnPQTaRcxvAgMBAAECggEAWAnFNHOefKRjY4MEcUmeirAJyyKKnGvYbST61t6ulzdXPRzCX08Fx5xo2lh93vz6sxZTgLGKAB3XPTwwv/DAk00DYjqqPmZvOQh5zZGcDXbkMhwktoffJqNhbsa6FX9KZQ54VLgavPSg5bqtLg4M4x1n/opyyAWBO3E4TmfxvRoNu/8d2rlJ+cLeLqPZiCMWHqjgFx0KQcUlQVe6neXDS1zK7NFp8EnG9JGdHweYBsU3DdAw4yvRg/0AudZwBzONF4YfZuXAYZiHO/WwU7pdMaQPGexXTqtIg5vd+uDNPeoMczptglgD8CYbymT3bxk+YvKXK0yycb1fAEM2C557AQKBgQDEP9wfx89tvls5r11UwQNCRrrT0Wqe1i8NZtIrDsiJZz/Nb6WdYsnXqmWXCbEyesimD0xjpCSv9V8RVwE6Lq/9SgVzm/RSyiNKtHGtrD1Erqijl5GBoCcZJoCOiAB/R4V5nkWUF4A3hOYWVxQf+B7V/K1krbkg5M9HFdFOlA23hQKBgQC/sBTEn3ESFxQqU/GmVTAD33En3Hm+CusU8igQP2i5ZbH32pj0Wyxf3Ul98dZN64UCnGXxp1x+hkq4H44g/mRN3812LqbcN0KxNPVKFGhoClaDw72bRlLtPExumwps02Xw1gc0M8/QMKZt+5zOmUqpgQ41OoYkRSDwqECWQX7EYwKBgHWiodwa9WefFye4yoUnPUDZDNwzR2n2kTXDUG+m6OYUEdae+fMhaEPyS/sBQEo191gzC2Me3S7sMhQ+xumNWsjFOgdWkFmf+Q+qogmsmP02hLeq/vloeodE4QKO211wDb4c9TAT9jNRYmo5wEJ5hGJYl8clqzbgcK73kQM9FAvRAoGAJCAMGe4ugglFbKC7VuyRCvnOOoPrkaw/F4h3knBQzTfkLWDOGKciGsL6ebjc+XxcadyNvdgbr2ChrkeMIp2uy5pU/2PVYIUtlXX0kEx+TLU+DsER97RuJnWJtgKUGWRRvuynGOh2zraMdwfHSoxLLNy8j72C0E0S4yfiXC7ltB8CgYEAmrswkxlS1Lna6Og2Ea9Ih0gZFT9abvc8UJg6aX1RI6LWsoOTRrsy6etJXh+NZU7+0PVFV4fXwASx0Uayp9hwYkLPVyPOmgINwNnEiyoCwpygvHxkFTOc4vweWRyoTUDPge5/Ua6Q81e/pwr5yRr7SUWx7ps+NOfr6b5aYJoC/PA=";

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode((SECRET_KEY));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpriation(token).before(new Date());
    }

    private Date extractExpriation(String token) {
        return extractClaims(token, Claims::getExpiration);
    }
}
