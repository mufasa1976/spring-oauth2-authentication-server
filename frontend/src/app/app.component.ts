import {Component} from '@angular/core';
import {Store} from '@ngrx/store';
import {ApplicationState} from './store';

@Component({
  selector: 'app-root',
  template: `
    <router-outlet></router-outlet>
  `,
  styles: []
})
export class AppComponent {
  constructor(private _store: Store<ApplicationState>) {}
}
