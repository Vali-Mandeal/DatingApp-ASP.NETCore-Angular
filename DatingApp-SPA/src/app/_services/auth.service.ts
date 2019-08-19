import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import {map} from 'rxjs/operators';
import {JwtHelperService} from '@auth0/angular-jwt';
import { environment } from '../../environments/environment';
import { User } from '../_models/user';

// Components are Injectable by default, but services are not, therefore we need to provide this decorator
@Injectable({
  providedIn: 'root' // root means app.module.ts in this case
})
export class AuthService {
  baseUrl = environment.apiUrl + 'auth/';
  jwtHelper = new JwtHelperService();
  decodedToken: any;
  currentUser: User;
  photoUrl = new BehaviorSubject<string>('../../assets/user.png');
  currentPhotoUrl = this.photoUrl.asObservable();
// We need the HttpClient coming from Angular Http not the other one
constructor(private http: HttpClient) { }
  changeMemberPhoto(photoUrl: string) {
    this.photoUrl.next(photoUrl);
  }

login(model: any) {
  return this.http.post(this.baseUrl + 'login', model)
    .pipe( // Pipe method allows us to chain rxjs operators to our request
      map((response: any) => {
        const user = response;
        if (user) {
          localStorage.setItem('token', user.token); // The third overload allows sending a header, we don't need it now
          localStorage.setItem('user', JSON.stringify(user.user));
          this.decodedToken = this.jwtHelper.decodeToken(user.token);
          this.currentUser = user.user;
          this.changeMemberPhoto(this.currentUser.photoUrl);
        }
      })
    );
}
  // The register method still returns an observable (it's post method),
  // so in order to use it we need to subscribe to it inside our component
  register(user: User) {
    return this.http.post(this.baseUrl + 'register', user);
  }

  loggedIn() {
    const token = localStorage.getItem('token');
    return !this.jwtHelper.isTokenExpired(token);
  }
}
