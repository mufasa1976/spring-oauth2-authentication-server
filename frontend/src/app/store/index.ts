import {routerReducer, RouterReducerState} from '@ngrx/router-store';
import {ActionReducerMap, MetaReducer} from '@ngrx/store';
import {environment} from '../../environments/environment';
import {storeFreeze} from 'ngrx-store-freeze';
import {CustomRouterState} from './router-state';

export {CustomRouterStateSerializer} from './router-state';

export interface ApplicationState {
  router: RouterReducerState<CustomRouterState>
}

export const reducers: ActionReducerMap<ApplicationState> = {
  router: routerReducer
};

export const metaReducers: MetaReducer<ApplicationState>[] = !environment.production
  ? [storeFreeze as MetaReducer<ApplicationState>]
  : [];
