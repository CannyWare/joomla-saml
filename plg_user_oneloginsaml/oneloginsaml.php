root@pb:/var/lib/docker/volumes/769f2f5e9c34614c66eb0b01fd72a7429ac852483fd6c24650bd1e50941a3c64/_data# cat plugins/user/oneloginsaml/oneloginsaml.php 
<?php
/**
 * @package     OneLogin SAML.Plugin
 * @subpackage  User.oneloginsaml
 *
 * @copyright   Copyright (C) 2014 OneLogin, Inc. All rights reserved.
 * @license     MIT
 */

if (!defined('_JEXEC')) {
    /**
     * Constant that is checked in included files to prevent direct access.
     * define() is used in the installation folder rather than "const" to not error for PHP 5.2 and lower
     */
    define('_JEXEC', 1);

    if (!defined('_JDEFINES')) {
        define('JPATH_BASE', dirname(dirname(dirname(dirname(__FILE__)))));
        require_once JPATH_BASE . '/includes/defines.php';
    }

    require_once JPATH_BASE . '/includes/framework.php';

    // Mark afterLoad in the profiler.
    JDEBUG ? $_PROFILER->mark('afterLoad') : null;

    // Instantiate the application.
    $app = JFactory::getApplication('site');
    $app->initialise();

//    $login_url = JRoute::_('../../../index.php?option=com_users&view=login', true);

//  this works but the menuitem is not selected
//    $login_url = JRoute::_('../../../index.php?option=com_content&view=article&id=15', true);
//    $redirectUrl = urlencode(base64_encode('index.php?option=com_content&view=article&id=15'));

    $login_url = JRoute::_('../../../index.php?Itemid=169', true);
    $redirectUrl = urlencode(base64_encode('index.php?Itemid=169'));

    $redirectUrl = '&return='.$redirectUrl;
    $home_url = $login_url . $redirectUrl;

    $oneLoginPlugin = JPluginHelper::getPlugin('user', 'oneloginsaml');

    if (!$oneLoginPlugin) {
        throw new Exception("Onelogin SAML Plugin not active");
    }

    $user = JFactory::getUser();
    $session = JFactory::getSession();

    jimport('joomla.html.parameter');
    $plgParams = new JRegistry();
    if ($oneLoginPlugin && isset($oneLoginPlugin->params)) {
        $plgParams->loadString($oneLoginPlugin->params);
    }

    $debug = $plgParams->get('onelogin_saml_advanced_settings_debug');

    jimport('onelogin.init');
    $saml_auth = onelogin_saml_instance($plgParams);

    if (isset($_GET['sso'])) {
        $saml_auth->login();
    } else if (isset($_GET['slo'])) {
        $saml_auth->logout();
    } else if (isset($_GET['acs'])) {
        $saml_auth->processResponse();

        jimport('joomla.user.authentication');
        $authenticate = JAuthentication::getInstance();
        $response = new JAuthenticationResponse();

        if (!$saml_auth->isAuthenticated()) {
            $msg_error = 'NO_AUTHENTICATED';
            $errors = $saml_auth->getErrors();

            if (!empty($errors) && $debug) {
                $msg_error .= '<br>'.implode(', ', $errors);
            }
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->message = $msg_error;
            $app->redirect($login_url, $response->message, 'error');
        }
        $attrs = $saml_auth->getAttributes();

        $username = '';
        $email = '';
        $name = '';

        if (empty($attrs)) {
            $username = $saml_auth->getNameId();
            $email = $username;
/*	    $response->status = JAuthentication::STATUS_FAILURE;
            return array( 'status' => LOGIN_ERROR_EXTERNAL_AUTH, 'error_msg'=> 'EMPTY_ATTRS', 'user_row'=> array('user_id' => $user->data['user_id']));
	    $app->redirect($login_url, $response->message, 'error');
*/	
	} else {
            $nameMapping = $plgParams->get('onelogin_saml_attr_mapping_name');
            $usernameMapping = $plgParams->get('onelogin_saml_attr_mapping_username');
	    $surnameMapping = 'urn:oid:2.5.4.4';
            $mailMapping = $plgParams->get('onelogin_saml_attr_mapping_mail');
            $groupsMapping = $plgParams->get('onelogin_saml_attr_mapping_groups');
            if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])) {
                $username = $attrs[$usernameMapping][0];
            }
/*	    if (empty($username)) {
		$username = $saml_auth->getNameId();
	    }
*/
            if (!empty($mailMapping) && isset($attrs[$mailMapping]) && !empty($attrs[$mailMapping][0])) {
                $email = $attrs[$mailMapping][0];
            }
/*	    if (empty($email)) {
	        $email = $username;
	    }
*/
            if (!empty($nameMapping) && isset($attrs[$nameMapping]) && !empty($attrs[$nameMapping][0])) {
/*                $name = $attrs[$nameMapping][0];
*/
            	$name = $attrs[$nameMapping][0].' '.$attrs[$surnameMapping][0];
/*		echo 'Cool.. this has been executed :-) ';
		printf($name);
*/
	    }
            if (!empty($groupsMapping) && isset($attrs[$groupsMapping]) && !empty($attrs[$groupsMapping])) {
                $saml_groups = $attrs[$groupsMapping];
/*            	echo 'We do seem to have saml_groups...';
		print_r($saml_groups);
*/
	    } else {
                $saml_groups = array();
/*		echo 'They say we dont have saml_groups..., printing the attrs after this line';
		print_r($attrs);
*/
            }
        }

        $matcher = $plgParams->get('onelogin_saml_account_matcher', 'username');


        if (empty($username) && $matcher == 'username') {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->message = 'NO_USERNAME, these are the attrs: '.print_r($attrs);
            $app->redirect($login_url, $response->message, 'error');
        }
        if (empty($email) && $matcher == 'mail') {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->message = 'NO_MAIL, these are the attrs: '.print_r($attrs);
            $app->redirect($login_url, $response->message, 'error');
        }

        $result = get_user_from_joomla($matcher, $username, $email);

        if (!$result) {
            // User not found, check if could be created
            $autocreate = $plgParams->get('onelogin_saml_autocreate');

            if ($autocreate) {
                if (empty($username)) {
                    $username = $email;
                }

                // user data
                $data['name'] = (isset($name) && !empty($name)) ? $name : $username;
                $data['username'] = $username;
                $data['email'] = $data['email1'] = $data['email2'] = JStringPunycode::emailToPunycode($email);
                $data['password'] = $data['password1'] = $data['password2'] = JUserHelper::genRandomPassword();

                // Get the model and validate the data.
                jimport('joomla.application.component.model');

                if (!defined('JPATH_COMPONENT')) {
                    define('JPATH_COMPONENT', JPATH_BASE . '/components/');
                }

                JModelLegacy::addIncludePath(JPATH_BASE . '/components/com_users/models');
                $model = JModelLegacy::getInstance('Registration', 'UsersModel');

                $return = $model->register($data);
		printf($return);
                if ($return === false) {
                    $errors = $model->getErrors();
                    print_r($data);
                    $response->status = JAuthentication::STATUS_FAILURE;
                    $response->message = 'USER NOT EXISTS AND FAILED THE CREATION PROCESS'.print_r($errors);
                    $app->redirect($login_url, $response->message, 'error');
                }

                $result = get_user_from_joomla($matcher, $username, $email);

                $user = JUser::getInstance($result->id);

                $user->set('block', '0');
                $user->set('activation', '');
                $user->save();


                $groups = get_mapped_groups($plgParams, $saml_groups);
/*		print_r($plgParams);
		print_r($saml_groups);
		print_r($groups);
*/
                if (empty($groups)) {
                    $params = JComponentHelper::getParams('com_users');
                    // Get the default new user group, Registered if not specified.
                    $system = $params->get('new_usertype', 2);
                    $groups[] = $system;
/*		    echo 'It seems groups is empty. :-(';
*/
                }

                $user->set('groups', $groups);
                $user->save();

                $response->status == JAuthentication::STATUS_SUCCESS;
                $session->set('user', $user);

                // SSO SAML Login flag
                $session->set('saml_login', 1);

/*                $app->redirect($login_url, "Welcome $user->username", 'message');
 
*/
//               $app->redirect($home_url, "Welcome $user->username", 'message');
//               $app->redirect($home_url);
            echo '<script type="text/javascript">window.top.location.href = "https://www.cannyware.net/index.php/nl/uw-motor"</script>';

            } else {
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->message = 'USER DOES NOT EXIST AND NOT ALLOWED TO CREATE';
                $app->redirect($login_url, $response->message, 'error');
            }
        } else {
            $user = JUser::getInstance($result->id);

            // User found, check if data should be update
            $autoupdate = $plgParams->get('onelogin_saml_updateuser');

            if ($autoupdate) {
                // TODO Update
                if (isset($name) && !empty($name)) {
                    $user->set('name', $name);
                    $user->save();
                }

                $groups = get_mapped_groups($plgParams, $saml_groups);
                if (!empty($groups)) {
                    $user->set('groups', $groups);
                    $user->save();
                }
            }

            $response->status == JAuthentication::STATUS_SUCCESS;
            $session->set('user', $user);

            // SSO SAML Login flag
            $session->set('saml_login', 1);

//            $app->redirect($home_url, "Welcome $user->username", 'message');
//            $app->redirect($home_url);
	    echo '<script type="text/javascript">window.top.location.href = "https://www.cannyware.net/index.php/nl/uw-motor"</script>';
        }

    } else if (isset($_GET['sls'])) {
        $saml_auth->processSLO();
        $errors = $saml_auth->getErrors();
        if (empty($errors)) {
            // TODO Do local logout
            $app->redirect($login_url, 'Sucessfully logged out', 'message');
        } else {
            $app->redirect($login_url, implode(', ', $errors), 'error');
        }
    } else if (isset($_GET['metadata'])) {
        $settings = $saml_auth->getSettings();
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);
        if (empty($errors)) {
            header('Content-Type: text/xml');
            echo $metadata;
        } else {
            throw new OneLogin_Saml2_Error(
                'Invalid SP metadata: '.implode(', ', $errors),
                OneLogin_Saml2_Error::METADATA_SP_INVALID
            );
        }
    } else {
        throw new Exception("No action selected, set one of those GET parameters: 'sso', 'slo', 'acs', 'sls' or 'metadata' .");
    }

} else {

    // We can't use the normal login process. We don't require user to click on Login
    // Joomla form providing credentials

    class PlgUserOneloginsaml extends JPlugin
    {
    /*
        public function onUserAuthenticate($credentials, $options, &$response)
        {
            // We redirect to initiate the SSO Login
            // $app = JFactory::getApplication();
            // $sso_url = JURI::base().'plugins/user/oneloginsaml/oneloginsaml.php?sso';
            // $app->redirect($sso_url);
        }
    */
        public function onUserLogout($parameters, $options)
        {
            if ($this->params->get('onelogin_saml_slo')) {

                $session = JFactory::getSession();

                if ($session->get('saml_login')) {
                    jimport('onelogin.init');
                    $saml_auth = onelogin_saml_instance($this->params);
                    $saml_auth->logout();
                }
            }
        }
    }
}
