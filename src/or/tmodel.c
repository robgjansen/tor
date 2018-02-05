/*
 * tmodel.c
 *
 *  Created on: Feb 3, 2018
 *      Author: rjansen
 */

#include <stdio.h>
#include <stdint.h>
#include <strings.h>

#include "torlog.h"
#include "util.h"
#include "util_bug.h"

#define TRAFFIC_MODEL_MAGIC 0xAABBCCDD
#define TRAFFIC_STREAM_MAGIC 0xDDCCBBAA

#define MAX_STATE_STR_LEN 63
#define MAX_OBS_STR_LEN 7

//const char* json_sample_string = "{\"observation_space\":[\"+\";\"-\";\"F\"];\"emission_probability\":{\"m1s6\":{\"+\":[0.010939649249180757;13.999999763708802;0.01];\"-\":[0.9890603507508193;5.1326143722028155;2.0751443522931985]};\"m1s5\":{\"+\":[0.6802762685957099;5.986558506074888;3.8556087518521496];\"-\":[0.31972373140429017;11.758608357839389;2.0780822206037617]};\"m1s4\":{\"+\":[0.3971745247006447;6.130164225667936;3.670383430203266];\"-\":[0.6028254752993554;0.6931471805599443;0.01]};\"m1s3\":{\"+\":[0.059921283701161315;9.598698928969446;2.507298346741341];\"-\":[0.9400787162988387;4.565974358136718;2.922021090949124]};\"m1s2\":{\"-\":[1.0;3.9426711195201927;1.3568069433177068]};\"m1s1\":{\"-\":[1.0;0.6931471805600146;0.01]};\"m1s0\":{\"-\":[1.0;3.378366236451709;2.2960840174026274]};\"m1s9\":{\"+\":[0.001476482802380788;6.999422467507961;0.01];\"-\":[0.9985235171976193;2.9957322735539993;0.01]};\"m1s8\":{\"+\":[0.23275524840240017;6.886743302334404;0.4702674349055173];\"-\":[0.7672447515975999;9.037740233423934;1.4920702074420324]};\"m0sEnd\":{\"F\":[1.0;10.183191288053328;4.020043044275213]};\"m4s10\":{\"-\":[1.0;10.999997633112407;0.01]};\"m4s11\":{\"-\":[1.0;1.555300804730652;0.8783208933285183]};\"m4s12\":{\"+\":[0.9789539814606759;4.952214890473033;2.464189815071575];\"-\":[0.021046018539324064;4.118549773244136;3.994922173482833]};\"m4s13\":{\"+\":[0.33333333333333337;1.809872281823449;1.2612260524196843];\"-\":[0.6666666666666667;9.890843713282452;3.958449272493786]};\"m4s14\":{\"+\":[1.0;1.9831764363517448;1.101589191895806]};\"m3s9\":{\"+\":[1.0;3.191409610279003;0.9016119885235871]};\"m3s8\":{\"+\":[1.0;4.12521000470585;2.328038058656329]};\"m3sEnd\":{\"F\":[1.0;13.91977461203617;2.2050893953416186]};\"m5s9\":{\"+\":[0.9338301338375816;9.310339466509543;1.3618278671899413];\"-\":[0.06616986616241835;4.219740675977248;3.2729478719184124]};\"m5s8\":{\"+\":[0.03171714718732423;9.04782091446962;1.3138563179976268];\"-\":[0.9682828528126758;8.280411031757424;2.8953879338749244]};\"m5s2\":{\"-\":[1.0;0.6931471805599454;0.01]};\"m5s1\":{\"-\":[1.0;0.6931471805599423;0.009999999999999998]};\"m5s0\":{\"+\":[0.9450553700850784;1.9721793914951076;1.626292081744794];\"-\":[0.054944629914921585;8.092434961750929;2.055710032769865]};\"m5s7\":{\"+\":[2.2736565911829896e-05;16.999999968802452;0.009999999999999998];\"-\":[0.9999772634340881;2.2665552332576047;1.2767745304808946]};\"m5s6\":{\"+\":[0.0002777906384555594;1.7371163209727518;0.46687719287501184];\"-\":[0.9997222093615444;8.41506146339043;2.3485391308101384]};\"m5s5\":{\"-\":[1.0;2.995732273554015;0.01]};\"m5s4\":{\"+\":[1.0;2.3817976531388987;1.8031849977128815]};\"m6sEnd\":{\"F\":[1.0;16.674184126156806;1.2398396598137364]};\"m6s10\":{\"+\":[1.0;2.8918378789563537;2.1600237865807137]};\"m5s14\":{\"+\":[1.0;6.337458026164865;0.8203823297285975]};\"m5s13\":{\"+\":[0.043351607954746976;8.496518227841419;2.03362166849406];\"-\":[0.956648392045253;1.9763770625064008;1.2850387028407526]};\"m5s12\":{\"-\":[1.0;3.988984046564273;0.009999999999999998]};\"m5s11\":{\"+\":[1.0;7.851961177703812;3.773017962128586]};\"m5s10\":{\"-\":[1.0;0.6931471805599453;0.01]};\"m1s13\":{\"-\":[1.0;11.553233130647792;0.5434143574035668]};\"m1s12\":{\"-\":[1.0;4.294777087054357;2.2706029443599927]};\"m1s11\":{\"-\":[1.0;0.6931471805600233;0.01]};\"m1s15\":{\"-\":[1.0;4.568194606678242;2.890296035402213]};\"m1s14\":{\"-\":[1.0;1.9459101490554116;0.01]};\"m3s1\":{\"+\":[0.6713342105913138;10.50169060974096;3.6332398068019036];\"-\":[0.32866578940868624;5.84067944219178;4.230584002914137]};\"m3s0\":{\"+\":[0.0009180579781660277;1.4126943954804616;0.9346394203541686];\"-\":[0.9990819420218339;4.877418313992135;3.271791271390003]};\"m3s3\":{\"-\":[1.0;0.6931471805597643;0.01]};\"m3s2\":{\"-\":[1.0;2.2658743204938867;1.6373636942159178]};\"m3s5\":{\"-\":[1.0;0.6931471805599481;0.01]};\"m3s4\":{\"+\":[0.00020284333194100997;1.5469874330787494;0.7421702551906709];\"-\":[0.9997971566680589;2.9333716400918632;0.9999983140598697]};\"m3s7\":{\"-\":[1.0;2.902323781631883;2.2870799325150153]};\"m3s6\":{\"+\":[0.7896357316760548;10.725006314637087;3.408481747840961];\"-\":[0.2103642683239452;9.725153206894419;1.4533268715861396]};\"m4s8\":{\"-\":[1.0;3.019089967949886;1.6998622043957567]};\"m4s9\":{\"+\":[1.0;8.101499967003427;0.34373335793679444]};\"m1sEnd\":{\"F\":[1.0;4.527748983839587;2.2678180925632656]};\"m4s2\":{\"+\":[6.584702794736e-05;7.999678579499451;0.01];\"-\":[0.9999341529720527;2.0686536930876587;0.8820345163050397]};\"m4s3\":{\"+\":[0.9961708719802569;4.110298254267704;1.2592147800766151];\"-\":[0.0038291280197431644;5.693685939675946;4.1976275691280485]};\"m4s0\":{\"+\":[0.21537147736976944;1.5141091861023983;1.18004576410213];\"-\":[0.7846285226302306;3.51614645306408;1.505840742770918]};\"m4s1\":{\"+\":[0.9948509481548512;7.735784747941672;2.2747402950129048];\"-\":[0.005149051845148891;11.368416747829604;0.9846490686672437]};\"m4s6\":{\"+\":[1.0;4.1307037462191785;0.8416873776074199]};\"m4s7\":{\"+\":[0.992577376059042;4.145502184812064;1.7706757533933373];\"-\":[0.007422623940957987;7.405593662994284;5.01835101448898]};\"m4s4\":{\"+\":[0.9941577408604229;4.804184864261106;2.171568674693005];\"-\":[0.005842259139577084;2.019958203824334;1.1877394593950856]};\"m4s5\":{\"-\":[1.0;2.051062998454741;1.276369571791786]};\"m6s4\":{\"+\":[0.50733029444376;9.217801947701217;1.9141762676468566];\"-\":[0.49266970555624007;5.418451383953838;1.4077597245393316]};\"m6s5\":{\"+\":[1.0;5.0502222842829605;1.7332724635249663]};\"m6s6\":{\"-\":[1.0;11.234573492177212;0.9540886418791527]};\"m6s7\":{\"+\":[0.23344361576851902;2.9103046479080508;1.7517512921332694];\"-\":[0.7665563842314811;11.441181608825945;0.4965275160596036]};\"m6s1\":{\"-\":[1.0;2.148123594793602;1.6212400816362569]};\"m6s2\":{\"-\":[1.0;2.03211941910644;1.3372291050958822]};\"m6s3\":{\"-\":[1.0;1.2512102867415764;0.7080548319307012]};\"m6s8\":{\"-\":[1.0;1.665038893087571;0.9976098390021542]};\"m6s9\":{\"+\":[0.9566815963633933;9.340850325633985;2.6021365752006598];\"-\":[0.04331840363660673;16.627314688749355;1.1679867258788088]};\"m2sEnd\":{\"F\":[1.0;9.920984940453248;1.5821277908748395]};\"m2s10\":{\"+\":[1.0;9.08511919262242;0.2852193275181275]};\"m2s11\":{\"-\":[1.0;8.969695611812762;3.1410229154376887]};\"m0s6\":{\"+\":[0.002409239809440606;0.6931471805599457;0.01];\"-\":[0.9975907601905595;8.694326888042378;2.608423899658795]};\"m0s7\":{\"-\":[1.0;1.3293419450897175;0.8299221323903758]};\"m0s4\":{\"+\":[0.8603692789196117;7.586842505856025;3.44328647271633];\"-\":[0.1396307210803884;7.325817975624356;3.4494657962959683]};\"m0s5\":{\"+\":[0.6320803586013917;7.419244057957895;3.8434761720542205];\"-\":[0.3679196413986083;9.34441593517758;3.940394442602817]};\"m0s2\":{\"+\":[1.0;3.0511182299222277;1.792722927350526]};\"m0s3\":{\"+\":[3.227894170261734e-05;2.7139787114284957;0.9045375818134501];\"-\":[0.9999677210582975;1.9898361977214711;1.2122689122852806]};\"m0s0\":{\"+\":[0.8099801787719907;11.999995137340928;0.01];\"-\":[0.1900198212280093;5.516149605954191;3.0706394584396577]};\"m0s1\":{\"+\":[0.0007119654653736085;3.8418886024501258;1.7415365035432582];\"-\":[0.9992880345346263;1.3620391452794036;0.8810156529601049]};\"m0s8\":{\"-\":[1.0;1.475767511602623;0.9249477290425022]};\"m0s9\":{\"+\":[0.0016864532744350939;1.9459101490553097;0.01];\"-\":[0.9983135467255648;1.5430843370030616;0.9911095795232491]};\"m3s11\":{\"+\":[1.0;0.8696144676452224;0.4358958343344941]};\"m3s10\":{\"+\":[1.0;5.358620283993609;1.5201529981455322]};\"m3s12\":{\"-\":[1.0;7.035581505483467;2.7171391712143875]};\"m3s15\":{\"-\":[1.0;1.945910149055387;0.01]};\"m3s14\":{\"+\":[0.00019277250187282413;6.081999981654045;3.7818660167938134];\"-\":[0.999807227498127;4.053195936959341;2.141338092427437]};\"m2s0\":{\"+\":[0.8324293181222403;11.01293247004973;1.0567235379759865];\"-\":[0.16757068187775967;12.709675271472248;0.520147463367743]};\"m2s1\":{\"+\":[1.0;11.725441516614305;0.6412727101923817]};\"m2s2\":{\"+\":[1.0;2.837056304505527;1.9266093414570766]};\"m2s3\":{\"+\":[0.2781048610316234;10.948677153063754;1.6232632656213284];\"-\":[0.7218951389683766;6.899720267138424;1.3485214600263886]};\"m2s4\":{\"+\":[0.19655024902167295;8.281073927186304;2.647124611662931];\"-\":[0.803449750978327;6.058101949710143;3.988507744522249]};\"m2s5\":{\"+\":[0.23858316806304264;4.294816852688886;3.1950296654401624];\"-\":[0.7614168319369573;10.367014330781762;1.8696823086471939]};\"m2s6\":{\"-\":[1.0;0.937439330562447;0.5009256771907029]};\"m2s7\":{\"+\":[1.0;1.3064689719970444;0.9693114636639333]};\"m2s8\":{\"-\":[1.0;8.70024006204888;3.2376785022543095]};\"m2s9\":{\"-\":[1.0;1.093125405365795;0.7067327465850565]};\"m0s14\":{\"-\":[1.0;1.5397435411284706;0.9838405244623166]};\"m0s15\":{\"+\":[1.0;0.6931471805598993;0.01]};\"m0s10\":{\"-\":[1.0;1.6110859061291167;1.2538943176005322]};\"m0s11\":{\"+\":[0.4476114185871532;11.268064272130253;1.8299198626362292];\"-\":[0.5523885814128469;9.024045347492311;3.7931998314930215]};\"m0s12\":{\"-\":[1.0;4.694467939194742;3.5792631222126476]};\"m0s13\":{\"+\":[0.6669969634810282;4.976429343467929;2.582980845440365];\"-\":[0.3330030365189717;11.643850705980519;0.49200668861893565]};\"m5sEnd\":{\"F\":[1.0;9.709193020882996;1.7750774170228905]};\"m4sEnd\":{\"F\":[1.0;1.1131382064066822;0.8964261852898402]}};\"start_probability\":{\"m1s5\":0.01825468701423338;\"m1s4\":0.02110677065733094;\"m4s9\":0.050573795974642136;\"m2s10\":0.030724104837728597;\"m4s1\":0.0005068869033941146;\"m0s11\":0.49732363715007905;\"m5s11\":0.013368297265514117;\"m1s8\":0.0003717170624890175;\"m5s9\":0.06229302118111406;\"m2s3\":0.00394020086238359;\"m0s0\":0.006427325935037376;\"m3s1\":0.09572052283694461;\"m6s9\":0.13643367891755992;\"m3s6\":0.06295535340154905};\"state_space\":[\"m0s2\";\"m0s11\";\"m0s5\";\"m0sEnd\";\"m0s12\";\"m0s8\";\"m0s7\";\"m0s9\";\"m0s4\";\"m0s13\";\"m0s15\";\"m0s14\";\"m0s3\";\"m0s10\";\"m0s1\";\"m0s0\";\"m0s6\";\"m1s0\";\"m1s12\";\"m1s9\";\"m1s15\";\"m1s1\";\"m1s4\";\"m1s14\";\"m1s13\";\"m1s8\";\"m1s11\";\"m1s5\";\"m1s6\";\"m1s3\";\"m1sEnd\";\"m1s2\";\"m2s0\";\"m2s4\";\"m2s5\";\"m2s8\";\"m2s10\";\"m2s3\";\"m2s6\";\"m2s7\";\"m2s2\";\"m2sEnd\";\"m2s1\";\"m2s11\";\"m2s9\";\"m3s6\";\"m3s1\";\"m3sEnd\";\"m3s2\";\"m3s3\";\"m3s8\";\"m3s14\";\"m3s0\";\"m3s7\";\"m3s12\";\"m3s4\";\"m3s5\";\"m3s15\";\"m3s9\";\"m3s10\";\"m3s11\";\"m4s13\";\"m4s5\";\"m4s9\";\"m4sEnd\";\"m4s10\";\"m4s3\";\"m4s4\";\"m4s12\";\"m4s0\";\"m4s6\";\"m4s7\";\"m4s8\";\"m4s1\";\"m4s2\";\"m4s11\";\"m4s14\";\"m5s14\";\"m5s13\";\"m5s4\";\"m5s6\";\"m5s7\";\"m5s10\";\"m5s9\";\"m5s5\";\"m5s2\";\"m5s11\";\"m5s1\";\"m5s8\";\"m5s12\";\"m5sEnd\";\"m5s0\";\"m6s1\";\"m6s8\";\"m6s3\";\"m6s6\";\"m6s4\";\"m6s2\";\"m6s7\";\"m6s9\";\"m6s5\";\"m6sEnd\";\"m6s10\"];\"transition_probability\":{\"m1s6\":{\"m1s6\":0.5733545015159799;\"m1s5\":0.23207668050564764;\"m1s0\":0.19456881797837247};\"m1s5\":{\"m1s13\":0.2833405108099692;\"m1s4\":0.43478635696830076;\"m1s3\":0.13185154170020114;\"m1sEnd\":0.1500215905215289};\"m1s4\":{\"m1s5\":0.4079010158634797;\"m1s15\":0.5902286019777352;\"m1s8\":0.0018703821587850846};\"m1s3\":{\"m1s4\":0.3127249374666302;\"m1s3\":0.0724302908807396;\"m1sEnd\":0.039485594615649315;\"m1s0\":0.5753591770369809};\"m1s2\":{\"m1s6\":0.9428570086031445;\"m1sEnd\":0.057142991396855525};\"m1s1\":{\"m1s3\":0.44436717540108567;\"m1sEnd\":0.0018825647899673725;\"m1s1\":0.553750259808947};\"m1s0\":{\"m1s12\":0.2563565679894107;\"m1s5\":0.010516285039345454;\"m1s1\":0.38871016729422875;\"m1s14\":0.34441697967701507};\"m1s9\":{\"m1s0\":1.0};\"m1s8\":{\"m1s3\":0.01799452340585254;\"m1s8\":0.9820054765941475};\"m0sEnd\":{};\"m4s10\":{\"m4s11\":0.021021021021021023;\"m4s9\":0.033283283283283276;\"m4s7\":0.024399399399399394;\"m4sEnd\":0.9212962962962963};\"m4s11\":{\"m4s8\":0.05;\"m4s5\":0.95};\"m4s12\":{\"m4s10\":0.004947384955139612;\"m4s3\":0.9711533427483394;\"m4s13\":0.023611329256803856;\"m4sEnd\":0.0002879430397171205};\"m4s13\":{\"m4s2\":0.4192176870748299;\"m4sEnd\":0.14540816326530612;\"m4s5\":0.43537414965986393};\"m4s14\":{\"m4s3\":0.0004587565229212763;\"m4s1\":0.0620765496262478;\"m4s14\":0.937464693850831};\"m3s9\":{\"m3s0\":0.027420948616603255;\"m3s4\":0.0009881422924901157;\"m3s8\":0.9715909090909066};\"m3s8\":{\"m3s1\":0.22908721078057462;\"m3s11\":0.7709127892194254};\"m3sEnd\":{};\"m5s9\":{\"m5s9\":0.0007871127019644998;\"m5sEnd\":0.0034632958886437995;\"m5s8\":0.15742254028593006;\"m5s0\":0.24589363253531643;\"m5s6\":0.4890592840528954;\"m5s4\":0.10337413453524981};\"m5s8\":{\"m5s1\":0.2636382306463823;\"m5s14\":0.030703265577777538;\"m5s9\":0.7056585037758403};\"m5s2\":{\"m5s1\":0.9215686274509803;\"m5s12\":0.07843137254901959};\"m5s1\":{\"m5s1\":0.3966672976324816;\"m5s5\":0.6033327023675183};\"m5s0\":{\"m5s9\":0.05516270212493483;\"m5s8\":0.08921715915915662;\"m5s6\":0.5775217824410872;\"m5s4\":0.27809835627482127};\"m5s7\":{\"m5s7\":0.7611295734023767;\"m5s13\":0.23698325910944804;\"m5s11\":0.001887167488175182};\"m5s6\":{\"m5s7\":0.48641154058881136;\"m5sEnd\":0.1870456964651932;\"m5s13\":0.3216814267730232;\"m5s12\":0.0037038751794074578;\"m5s11\":0.0011574609935648304};\"m5s5\":{\"m5sEnd\":0.03760692979344534;\"m5s2\":0.04358985044240256;\"m5s9\":0.2188015055998506;\"m5s6\":0.7000017141643013};\"m5s4\":{\"m5sEnd\":0.0008837825906843235;\"m5s0\":0.9953601413989073;\"m5s11\":0.0037560760104083744};\"m6s10\":{\"m6s6\":1.0};\"m5s14\":{\"m5s8\":1.0};\"m5s13\":{\"m5sEnd\":0.28893337154468746;\"m5s9\":0.35922202677566484;\"m5s6\":0.35184460167964765};\"m5s12\":{\"m5s10\":1.0};\"m5s11\":{\"m5sEnd\":0.041109473310679524;\"m5s13\":0.002356228636994876;\"m5s11\":0.9565342980523256};\"m5s10\":{\"m5s5\":1.0};\"m1s13\":{\"m1s6\":0.12658023838294882;\"m1s3\":0.5447068479523111;\"m1s0\":0.32871291366474015};\"m1s12\":{\"m1s11\":1.0};\"m1s11\":{\"m1s12\":0.6860950840156506;\"m1s0\":0.3139049159843494};\"m1s15\":{\"m1s4\":0.24719716838464434;\"m1s2\":0.045824609165570684;\"m1s9\":0.15139709222887468;\"m1s0\":0.5555811302209103};\"m1s14\":{\"m1s4\":0.16852967712663963;\"m1s15\":0.13256271946235162;\"m1s0\":0.6989076034110088};\"m3s1\":{\"m3sEnd\":0.22654054523787778;\"m3s10\":0.01963468993566476;\"m3s12\":0.021688400436259116;\"m3s1\":0.010994602260123524;\"m3s0\":0.24395555429621688;\"m3s6\":0.47718620783385796};\"m3s0\":{\"m3s3\":0.1573650989282394;\"m3s14\":0.3261667981104009;\"m3s7\":0.5164681029613596};\"m3s3\":{\"m3s0\":0.17504932290258415;\"m3s2\":0.8230655252860325;\"m3s7\":0.0018851518113834058};\"m3s2\":{\"m3s3\":0.6630200133287677;\"m3s15\":0.21715625941308891;\"m3s4\":0.11982372725814347};\"m3s5\":{\"m3s0\":1.0};\"m3s4\":{\"m3sEnd\":0.014437158496308486;\"m3s10\":0.0032984089628668575;\"m3s12\":0.11303666602416282;\"m3s2\":0.8692277665166618};\"m3s7\":{\"m3s1\":0.12651463104107347;\"m3s3\":0.8734853689589264};\"m3s6\":{\"m3s1\":0.9380265321578641;\"m3s15\":0.061973467842135734};\"m4s8\":{\"m4s0\":0.8652283138761637;\"m4s12\":0.13477168612383628};\"m4s9\":{\"m4s10\":0.9903541058509964;\"m4s12\":0.0011422769386978044;\"m4s13\":0.007488259931463382;\"m4s4\":0.0010153572788424924};\"m4s2\":{\"m4s2\":0.9953624878888502;\"m4s11\":0.002746761737232733;\"m4s1\":0.0006678769977517941;\"m4s9\":0.0012228733761652576};\"m4s3\":{\"m4s4\":1.0};\"m4s0\":{\"m4s8\":0.9511528608027328;\"m4s7\":0.048847139197267284};\"m4s1\":{\"m4s6\":0.5402438708438865;\"m4s12\":0.06768293149076776;\"m4s14\":0.3767615434942452;\"m4s8\":0.015311654171100652};\"m4s6\":{\"m4s3\":0.008916825780297242;\"m4s6\":0.9910809371833466;\"m4s7\":2.2370363562755323e-06};\"m4s7\":{\"m4s12\":0.993755135577349;\"m4s13\":0.005888797591534937;\"m4sEnd\":0.0003560668311160659};\"m4s4\":{\"m4s14\":0.20273079562449023;\"m4s7\":0.7972692043755097};\"m4s5\":{\"m4s8\":1.0};\"m6s4\":{\"m6s5\":0.024516446963163734;\"m6s1\":0.06406307749168413;\"m6s2\":0.08069483799433275;\"m6s9\":0.8307256375508195};\"m6s5\":{\"m6s4\":0.0012323889146926765;\"m6s5\":0.9987676110853073};\"m6s6\":{\"m6sEnd\":0.29057222082177964;\"m6s4\":0.03609780690698261;\"m6s6\":0.04023191328459793;\"m6s1\":0.09654650869674815;\"m6s3\":0.1275775144945803;\"m6s8\":0.2514746659944543;\"m6s9\":0.15749936980085708};\"m6s7\":{\"m6s4\":0.19273257444064368;\"m6s9\":0.8072674255593564};\"m6s1\":{\"m6sEnd\":0.3621322207035466;\"m6s6\":0.20250341702035826;\"m6s9\":0.4353643622760952};\"m6s2\":{\"m6s1\":0.2907152984892192;\"m6s2\":0.7092847015107809};\"m6s3\":{\"m6s1\":0.23515328855489792;\"m6s2\":0.351865398683248;\"m6s9\":0.4129813127618541};\"m6s8\":{\"m6s3\":1.0};\"m6s9\":{\"m6sEnd\":0.06059897051941974;\"m6s10\":0.1446119393007554;\"m6s4\":0.05095594625309178;\"m6s6\":0.44464870646433585;\"m6s7\":0.29803128551373753;\"m6s1\":0.0011531519486596695};\"m2sEnd\":{};\"m2s10\":{\"m2s11\":0.28351262668765187;\"m2s5\":0.716487373312348};\"m2s11\":{\"m2s9\":0.05717130339206509;\"m2s10\":0.0875448958103994;\"m2s3\":0.025780270200685993;\"m2s4\":0.06150852223269988;\"m2s6\":0.7679950083641496};\"m0s6\":{\"m0s14\":0.3922292917609632;\"m0s9\":0.5039125590520771;\"m0s1\":0.10385814918695967};\"m0s7\":{\"m0s6\":0.98512390215163;\"m0s3\":0.01487609784836996};\"m0s4\":{\"m0s0\":0.06223960700196126;\"m0s13\":0.9377603929980387};\"m0s5\":{\"m0s15\":0.09174606187792429;\"m0s4\":0.6647588770944839;\"m0sEnd\":0.08763508357211966;\"m0s11\":0.15585997745547212};\"m0s2\":{\"m0s6\":0.15550238364730273;\"m0s15\":0.23184304553154347;\"m0s5\":0.014303942459307807;\"m0s2\":0.524839848754298;\"m0s11\":0.073510779607548};\"m0s3\":{\"m0s6\":0.0061071757701352;\"m0s3\":0.9932561221047805;\"m0s1\":0.0006367021250841273};\"m0s0\":{\"m0s2\":0.7500078704519266;\"m0s12\":0.2499921295480733};\"m0s1\":{\"m0s10\":0.4669010171316463;\"m0s11\":0.5330989828683538};\"m0s8\":{\"m0s14\":0.9380719778131518;\"m0s1\":0.06192802218684825};\"m0s9\":{\"m0s14\":0.7002398892959711;\"m0sEnd\":0.030445212578496063;\"m0s4\":0.021818141372229594;\"m0s5\":0.03077916372276963;\"m0s0\":0.10033561953816035;\"m0s1\":0.11638197349237313};\"m3s11\":{\"m3s10\":0.9981966634436823;\"m3s6\":0.0018033365563176597};\"m3s10\":{\"m3s11\":0.9388270140389584;\"m3s9\":0.06117298596104165};\"m3s12\":{\"m3s12\":0.275396115051875;\"m3s5\":0.7246038849481249};\"m3s15\":{\"m3s7\":1.0};\"m3s14\":{\"m3s1\":0.006120526935017157;\"m3s14\":0.8300969826423049;\"m3s4\":0.16378249042267784};\"m2s0\":{\"m2s3\":0.7459412877169052;\"m2s5\":0.2540587122830948};\"m2s1\":{\"m2s7\":1.0};\"m2s2\":{\"m2s2\":0.5999888968124577;\"m2s3\":0.4000111031875422};\"m2s3\":{\"m2s10\":0.015833444394669497;\"m2s2\":0.0034551663053829264;\"m2s3\":0.8531762580957591;\"m2s5\":0.04289360977446942;\"m2s6\":0.06261747035126024;\"m2s9\":0.022024051078458656};\"m2s4\":{\"m2s3\":0.010276035383052134;\"m2s4\":0.9857671464757269;\"m2s7\":0.003956818141220903};\"m2s5\":{\"m2s8\":0.2900401696383759;\"m2sEnd\":0.7092915280424885;\"m2s7\":0.00066830231913551};\"m2s6\":{\"m2s8\":0.05098862435568371;\"m2s9\":0.1989865234631587;\"m2s10\":0.01918298395403538;\"m2sEnd\":0.07842196628010695;\"m2s6\":0.6524199019470153};\"m2s7\":{\"m2s11\":0.19172267011266195;\"m2s5\":0.14998232161533437;\"m2s7\":0.6582950082720036};\"m2s8\":{\"m2s9\":0.24132080552459656;\"m2s11\":0.09256096737597404;\"m2sEnd\":0.6369187325649514;\"m2s6\":0.02919949453447794};\"m2s9\":{\"m2s0\":0.06567156766856526;\"m2s1\":0.31807047214582473;\"m2s11\":0.6162579601856101};\"m0s14\":{\"m0s7\":0.1705102952708992;\"m0s8\":0.8294897047291009};\"m0s15\":{\"m0s15\":0.40209176653572354;\"m0s2\":0.5979082334642765};\"m0s10\":{\"m0s4\":0.13973251219958288;\"m0sEnd\":0.21831120241616123;\"m0s0\":0.6419562853842559};\"m0s11\":{\"m0s6\":0.2550192463086928;\"m0s5\":0.04870014177660558;\"m0s11\":0.570650213390658;\"m0sEnd\":0.1158436966406641;\"m0s3\":0.009786701883379394};\"m0s12\":{\"m0s3\":0.002221832943539733;\"m0s12\":0.9724464968480889;\"m0s1\":0.02533167020837134};\"m0s13\":{\"m0s6\":0.14100330875085648;\"m0s5\":0.8414332053244805;\"m0s3\":0.0008789733629267396;\"m0sEnd\":0.016684512561736337};\"m5sEnd\":{};\"m4sEnd\":{}}}";

/* the tmodel_stream internal elements (see tmodel.h for typedef) */
struct tmodel_stream_s {
    struct timeval creation_time;
    unsigned int magic;
};

/* An opaque structure representing a traffic model. The internals
 * of this structure are not intended to be accessed outside of the
 * tmodel class. */
typedef struct tmodel_s tmodel_t;

/* the tmodel internal elements */
struct tmodel_s {
    /* array of strings holding names of each observation
     * in the observation space */
    char** obs_space;
    /* the number of observations in obs_space.
     * (the length of the obs_space array). */
    unsigned int num_obs;

    /* array of strings holding names of each state
     * in the state space */
    char** state_space;
    /* the number of states in state_space.
     * (the length of the state_space array). */
    unsigned int num_states;

    /* array of size num_states where the start prob of
     * state state_space[i] is held in start_prob[i] */
    double* start_prob;

    /* matrix of size num_states*num_states
     * where the transition prob of src state
     * state_space[i] and dst state state_space[j]
     * is held in trans_prob[i][j] */
    double** trans_prob;

    /* matrices of size num_states*num_obs
     * where the emission value of state
     * state_space[i] and observation obs_space[j]
     * is held in emit_val[i][j] */
    double** emit_dp;
    double** emit_mu;
    double** emit_sigma;

    /* for memory checking */
    unsigned int magic;
};

/* global pointer to traffic model state */
tmodel_t* global_traffic_model = NULL;

/* returns true if we want to know about cells on exit streams,
 * false otherwise. */
int tmodel_is_active() {
    if (get_options()->EnablePrivCount && global_traffic_model != NULL &&
            global_traffic_model->magic == TRAFFIC_MODEL_MAGIC) {
      return 1;
    } else {
        return 0;
    }
}

static int _tmodel_get_state_index(tmodel_t* tmodel, char* state_name) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    for(int i = 0; i < tmodel->num_states; i++) {
        if(strncasecmp(tmodel->state_space[i], state_name, 63) == 0) {
            return i;
        }
    }

    log_warn(LD_GENERAL, "unable to find state index");
    return -1;
}

static int _tmodel_get_obs_index(tmodel_t* tmodel, char* obs_name) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    for(int i = 0; i < tmodel->num_obs; i++) {
        if(strncasecmp(tmodel->obs_space[i], obs_name, 7) == 0) {
            return i;
        }
    }

    log_warn(LD_GENERAL, "unable to find obs index");
    return -1;
}

static int _json_find_object_end_pos(const char* json) {
    /* start is the opening bracket or brace */
    char open = json[0];
    char close;
    if (open == '[') {
        close = ']';
    } else if (open == '{') {
        close = '}';
    } else {
        log_warn(LD_GENERAL, "unable to recognize object delimiter");
        return -1;
    }

    /* we start at depth one for the first char */
    int depth = 1;

    /* we need to find when the object closes */
    int i = 1;
    for(i = 1; json[i] != '\0' && depth > 0; i++) {
        if (json[i] == open) {
            depth++;
        } else if (json[i] == close) {
            depth--;
        }
    }

    /* if we found the close, return the position */
    if (depth == 0) {
        return i;
    } else {
        log_warn(LD_GENERAL, "object has incorrect depth");
        return -1;
    }
}

static int _parse_json_state_space(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;
    int count = 0;

    while (json[i] != ']' && i <= obj_end_pos) {
        char state_name[64];
        memset(state_name, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing state name");
            return -1;
        }

        /* process the state name */
        log_debug(LD_GENERAL, "found state '%s'", state_name);
        if(tmodel) {
            tmodel->state_space[count] = strndup(state_name, 63);
        }
        count++;

        /* fast forward to the end of the name,
         * plus 2 for the quote characters. */
        i += strnlen(state_name, 63) + 2;

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return count;
}
static int _parse_json_obs_space(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;
    int count = 0;

    while (json[i] != ']' && i <= obj_end_pos) {
        char obs_name[8];
        memset(obs_name, 0, 8);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%7[^\"]", obs_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing obs name");
            return 1;
        }

        /* process the state name */
        log_debug(LD_GENERAL, "found observation '%s'", obs_name);
        if(tmodel) {
            tmodel->obs_space[count] = strndup(obs_name, 7);
        }
        count++;

        /* fast forward to the end of the name,
         * plus 2 for the quote characters. */
        i += strnlen(obs_name, 7) + 2;

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return count;
}

static int _parse_json_emit_prob(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;

    while (json[i] != '}' && i <= obj_end_pos) {
        char state_name[64];
        memset(state_name, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing emit state name");
            return 1;
        }

        /* fast forward to the end of the name,
         * plus 3 for the quotes and the ':'. */
        i += strnlen(state_name, 63) + 3;

        /* we have another dict for dst states */
        int inner_dict_len = _json_find_object_end_pos(&json[i]);
        int inner_obj_end_pos = i + inner_dict_len;

        /* jump one past the start of the inner dict */
        if (json[i] != '{') {
            log_warn(LD_GENERAL, "expected opening brace in emit object");
            return 1;
        } else {
            i++;
        }

        int state_index = _tmodel_get_state_index(tmodel, state_name);
        if(state_index < 0) {
            log_warn(LD_GENERAL, "unable to find state index");
            return 1;
        }

        /* iterate the inner dict object */
        while(json[i] != '}' && i <= inner_obj_end_pos) {
            char obs[8];
            memset(obs, 0, 8);

            n_assigned = sscanf(&json[i], "\"%7[^\"]", obs);
            if (n_assigned != 1) {
                log_warn(LD_GENERAL, "sscanf problem parsing emit obs name");
                return 1;
            }

            /* fast forward to the end of the dst state name,
             * plus 3 for the quotes and the ':'. */
            i += strnlen(obs, 7) + 3;

            if(json[i] != '[') {
                log_warn(LD_GENERAL, "unable to find emit list start bracket");
                return 1;
            }

            int emit_vals_list_len = _json_find_object_end_pos(&json[i]);
            if (emit_vals_list_len < 0) {
                log_warn(LD_GENERAL, "unable to find emit list len");
                return 1;
            }

            int obs_index = _tmodel_get_obs_index(tmodel, obs);
            if(obs_index < 0) {
                log_warn(LD_GENERAL, "unable to find emit obs index");
                return 1;
            }

            double dp = 0.0, mu = 0.0, sigma = 0.0;
            n_assigned = sscanf(&json[i], "[%lf;%lf;%lf]", &dp, &mu, &sigma);
            if (n_assigned != 3) {
                log_warn(LD_GENERAL, "sscanf problem parsing emit values");
                return 1;
            }

            /* process the items */
            log_debug(LD_GENERAL,
                    "found emit for state '%s' and obs '%s': dp='%f' mu='%f' sigma='%f'",
                    state_name, obs, dp, mu, sigma);

            tmodel->emit_dp[state_index][obs_index] = dp;
            tmodel->emit_mu[state_index][obs_index] = mu;
            tmodel->emit_sigma[state_index][obs_index] = sigma;

            /* fast forward to one past the end of the list */
            i += emit_vals_list_len;

            /* check if we have another element, which is normally
             * separated by a comma, but we separate by a ';'. */
            if(json[i] == ';') {
                i++;
            }
        }

        if(json[i] != '}') {
            log_warn(LD_GENERAL, "unable to find emit closing brace");
            return 1;
        }

        /* jump ahead one, past the end of the inner dict */
        i++;

        /* fast forward to the next entry or the end */
        while(json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
            i++;
        }

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

static int _parse_json_trans_prob(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;

    while (json[i] != '}' && i <= obj_end_pos) {
        char state_name_src[64];
        memset(state_name_src, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name_src);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing trans src state name");
            return 1;
        }

        /* fast forward to the end of the name,
         * plus 3 for the quotes and the ':'. */
        i += strnlen(state_name_src, 63) + 3;

        /* we have another dict for dst states */
        int inner_dict_len = _json_find_object_end_pos(&json[i]);
        int inner_obj_end_pos = i + inner_dict_len;

        /* jump one past the start of the inner dict */
        if (json[i] != '{') {
            log_warn(LD_GENERAL, "unable to find trans open brace");
            return 1;
        } else {
            i++;
        }

        int src_index = _tmodel_get_state_index(tmodel, state_name_src);
        if(src_index < 0) {
            log_warn(LD_GENERAL, "unable to find trans src state index");
            return 1;
        }

        /* iterate the inner dict object */
        while(json[i] != '}' && i <= inner_obj_end_pos) {
            char state_name_dst[64];
            memset(state_name_dst, 0, 64);

            n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name_dst);
            if (n_assigned != 1) {
                log_warn(LD_GENERAL, "sscanf problem parsing trans dst state name");
                return 1;
            }

            /* fast forward to the end of the dst state name,
             * plus 3 for the quotes and the ':'. */
            i += strnlen(state_name_dst, 63) + 3;

            int dst_index = _tmodel_get_state_index(tmodel, state_name_dst);
            if(dst_index < 0) {
                log_warn(LD_GENERAL, "unable to find trans dst state index");
                return 1;
            }

            double trans_prob = 0.0;
            n_assigned = sscanf(&json[i], "%lf;", &trans_prob);
            if (n_assigned != 1) {
                log_warn(LD_GENERAL, "sscanf problem parsing trans prob val");
                return 1;
            }

            /* process the items */
            log_debug(LD_GENERAL, "found trans from '%s' to '%s' = '%f'",
                    state_name_src, state_name_dst, trans_prob);

            tmodel->trans_prob[src_index][dst_index] = trans_prob;

            /* fast forward to the next entry or the end */
            while(json[i] != ';' && json[i] != '}' && i < inner_obj_end_pos) {
                i++;
            }

            /* check if we have another element, which is normally
             * separated by a comma, but we separate by a ';'. */
            if(json[i] == ';') {
                i++;
            }
        }

        /* jump ahead one, past the end of the inner dict */
        i++;

        /* fast forward to the next entry or the end */
        while(json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
            i++;
        }

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

static int _parse_json_start_prob(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;

    while (json[i] != '}' && i <= obj_end_pos) {
        char state_name[64];
        memset(state_name, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing start state name");
            return 1;
        }

        /* fast forward to the end of the name,
         * plus 3 for the quotes and the ':'. */
        i += strnlen(state_name, 63) + 3;

        int state_index = _tmodel_get_state_index(tmodel, state_name);
        if(state_index < 0) {
            log_warn(LD_GENERAL, "unable to find start state name index");
            return 1;
        }

        double start_prob = 0.0;
        n_assigned = sscanf(&json[i], "%lf;", &start_prob);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing start prob");
            return 1;
        }

        /* process the items */
        log_debug(LD_GENERAL, "found state '%s' and start_prob '%f'",
                state_name, start_prob);

        tmodel->start_prob[state_index] = start_prob;

        /* fast forward to the next entry or the end */
        while(json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
            i++;
        }

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

/* we loop twice, once to parse the state space and observation
 * space which is only done if parse_spaces=1. on the second
 * pass, we parse the trans_prob, emit_prob, an start_prob
 * objects, given the space and observation spaces that we
 * parsed in the first step. */
int _parse_json_objects(const char* json, int parse_spaces, tmodel_t* tmodel) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    int i = 0, j = 0;
    if (json[i] != '{') {
        return 1;
    } else {
        i++;
    }

    while (json[i] != '}') {
        /* static buffer to hold the parsed type */
        char input_type[32];
        memset(input_type, 0, 32);

        /* read the type. will be one of the following:
         *   '"states"', '"emission_probability"',
         *   'transition_probability', 'start_probability'
         * they may appear in any order.
         */
        int n_assigned = sscanf(&json[i], "\"%30[^\"]", input_type);
        if (n_assigned != 1) {
            return 1;
        }

        /* fast forward to the object starting position,
         * which will be at 1 past the ':' character.
         * add 3 for the "": chars */
        i += strnlen(input_type, 30) + 3;

        /* find the end of the object */
        j = _json_find_object_end_pos(&json[i]);
        if (j < 0) {
            return 1;
        }

        log_info(LD_GENERAL, "found object '%s' of length %d", input_type, j);

        /* handle each object type */
        if (json[i] == '[' &&
                strncasecmp(input_type, "state_space", 6) == 0) {
            if(parse_spaces) {
                /* first count the number of states */
                int num_states = _parse_json_state_space(&json[i], j, NULL);
                if(num_states <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_state_space failed to count states (1)");
                    return 1;
                }

                /* allocate the state array */
                tmodel->num_states = num_states;
                tmodel->state_space = calloc(tmodel->num_states, sizeof(char*));

                /* now actually store the values by giving a model */
                num_states = _parse_json_state_space(&json[i], j, tmodel);
                if(num_states <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_state_space failed to count states (2)");
                    return 1;
                }
            }
        } else if (json[i] == '[' &&
                strncasecmp(input_type, "observation_space", 17) == 0) {
            if(parse_spaces) {
                /* first count the number of states */
                int num_obs = _parse_json_obs_space(&json[i], j, NULL);
                if(num_obs <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_obs_space failed to count obs (1)");
                    return 1;
                }

                /* allocate the obs array */
                tmodel->num_obs = num_obs;
                tmodel->obs_space = calloc(tmodel->num_obs, sizeof(char*));

                /* now actually store the values by giving a model */
                num_obs = _parse_json_obs_space(&json[i], j, tmodel);
                if(num_obs <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_obs_space failed to count obs (2)");
                    return 1;
                }
            }
        } else if (json[i] == '{' &&
                strncasecmp(input_type, "emission_probability", 20) == 0) {
            if(!parse_spaces && _parse_json_emit_prob(&json[i], j, tmodel) != 0) {
                log_warn(LD_GENERAL, "_parse_json_emit_prob failed");
                return 1;
            }
        } else if (json[i] == '{' &&
                strncasecmp(input_type, "transition_probability", 22) == 0) {
            if(!parse_spaces && _parse_json_trans_prob(&json[i], j, tmodel) != 0) {
                log_warn(LD_GENERAL, "_parse_json_trans_prob failed");
                return 1;
            }
        } else if (json[i] == '{' &&
                strncasecmp(input_type, "start_probability", 17) == 0) {
            if(!parse_spaces && _parse_json_start_prob(&json[i], j, tmodel) != 0) {
                log_warn(LD_GENERAL, "_parse_json_start_prob failed");
                return 1;
            }
        } else {
            return 1;
        }

        /* Jump to the end of the object, and add 1 to
         * get the the start of the next item. */
        i += j;

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

static void _tmodel_allocate_arrays(tmodel_t* tmodel) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    tmodel->start_prob = calloc(tmodel->num_states, sizeof(double));

    tmodel->trans_prob = calloc(tmodel->num_states, sizeof(double*));
    for(int i = 0; i < tmodel->num_states; i++) {
        tmodel->trans_prob[i] = calloc(tmodel->num_states, sizeof(double));
    }

    tmodel->emit_dp = calloc(tmodel->num_states, sizeof(double*));
    for(int i = 0; i < tmodel->num_states; i++) {
        tmodel->emit_dp[i] = calloc(tmodel->num_obs, sizeof(double));
    }

    tmodel->emit_mu = calloc(tmodel->num_states, sizeof(double*));
    for(int i = 0; i < tmodel->num_states; i++) {
        tmodel->emit_mu[i] = calloc(tmodel->num_obs, sizeof(double));
    }

    tmodel->emit_sigma = calloc(tmodel->num_states, sizeof(double*));
    for(int i = 0; i < tmodel->num_states; i++) {
        tmodel->emit_sigma[i] = calloc(tmodel->num_obs, sizeof(double));
    }
}

static void _tmodel_free(tmodel_t* tmodel) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    if(tmodel->start_prob) {
        free(tmodel->start_prob);
    }

    if(tmodel->trans_prob) {
        for(int i = 0; i < tmodel->num_states; i++) {
            if(tmodel->trans_prob[i]) {
                free(tmodel->trans_prob[i]);
            }
        }
        free(tmodel->trans_prob);
    }

    if(tmodel->emit_dp) {
        for(int i = 0; i < tmodel->num_states; i++) {
            if(tmodel->emit_dp[i]) {
                free(tmodel->emit_dp[i]);
            }
        }
        free(tmodel->emit_dp);
    }

    if(tmodel->emit_mu) {
        for(int i = 0; i < tmodel->num_states; i++) {
            if(tmodel->emit_mu[i]) {
                free(tmodel->emit_mu[i]);
            }
        }
        free(tmodel->emit_mu);
    }

    if(tmodel->emit_sigma) {
        for(int i = 0; i < tmodel->num_states; i++) {
            if(tmodel->emit_sigma[i]) {
                free(tmodel->emit_sigma[i]);
            }
        }
        free(tmodel->emit_sigma);
    }

    if(tmodel->state_space) {
        for(int i = 0; i < tmodel->num_states; i++) {
            if(tmodel->state_space[i]) {
                free(tmodel->state_space[i]);
            }
        }
        free(tmodel->state_space);
    }

    if(tmodel->obs_space) {
        for(int i = 0; i < tmodel->num_obs; i++) {
            if(tmodel->obs_space[i]) {
                free(tmodel->obs_space[i]);
            }
        }
        free(tmodel->obs_space);
    }

    tmodel->magic = 0;
    tor_free_(tmodel);
}

static tmodel_t* _tmodel_new(const char* model_json) {
    tmodel_t* tmodel = tor_malloc_zero_(sizeof(struct tmodel_s));
    tmodel->magic = TRAFFIC_MODEL_MAGIC;

    int ret = _parse_json_objects(json_string, 1, tmodel);
    if(ret == 0) {
        log_info(LD_GENERAL, "success parsing state and obs spaces");

        /* now we know the state and obs counts, allocate arrays */
        _tmodel_allocate_arrays(tmodel);

        /* now parse again, filling the arrays with probs */
        ret = _parse_json_objects(json_string, 0, tmodel);
        if(ret == 0) {
            log_info(LD_GENERAL, "success parsing trans, emit, and start probs");
        } else {
            log_warn(LD_GENERAL, "problem parsing trans, emit, and start probs");
        }
    } else {
        log_warn(LD_GENERAL, "problem parsing state and obs spaces");
    }

    if(ret == 0) {
        return tmodel;
    } else {
        _tmodel_free(tmodel);
        return NULL;
    }
}

/* returns 0 if the traffic model body is parsed correctly and
 * the traffic model is loaded and ready to run viterbi on
 * closed streams. returns 1 if there is an error. */
int tmodel_set_traffic_model(uint32_t len, char *body) {
  /* body is NULL terminated, valid command syntax is:
   *  'TRUE {}\r\n' : command is to set a new model, the {} part
   *                  represents the actual JSON representation
   *                  of the model. The model JSON may be of
   *                  arbitrary length.
   *  'FALSE\r\n' : command is to unset, or remove any existing
   *                model that we have stored.
   */
  char* model_json = NULL;

  /* check if we have a model */
  if(len >= 5 && strncasecmp(body, "TRUE ", 5) == 0) {
      /* this is a command to parse and store a new model */
      model_json = &body[5];
  }

  /* we always free the previous model- if the length is too
   * short or we have a 'FALSE' command, or we are creating
   * a new model object. */
  if(global_traffic_model != NULL) {
      _tmodel_free(global_traffic_model);
      global_traffic_model = NULL;
      log_notice(LD_GENERAL, "Successfully freed a previously loaded traffic model");
  }

  /* now create a new one only if we had valid command input */
  if(model_json != NULL) {
      global_traffic_model = _tmodel_new(model_json);
      if(global_traffic_model) {
          log_notice(LD_GENERAL, "Successfully loaded a new traffic model from PrivCount");
      } else {
          log_warn(LD_GENERAL, "Unable to load traffic model from PrivCount");
          return 1;
      }
  }

  return 0;
}

/* allocate storage for a new tmodel stream object that will be used
 * to track cell transmit times while a stream is active. */
tmodel_stream_t* tmodel_stream_new() {
    tmodel_stream_t* tstream = tor_malloc_zero_(sizeof(struct tmodel_stream_s));
    tstream->magic = TRAFFIC_STREAM_MAGIC;

    tor_gettimeofday(&tstream->creation_time);

    return tstream;
}

/* notify the traffic model that the stream closed and should
 * be processed and freed. */
void tmodel_stream_free(tmodel_stream_t* tstream) {
    tor_assert(tstream && tstream->magic == TRAFFIC_STREAM_MAGIC);

    // stream is done, we have all cells we need
    // run viterbi to get likliest paths
    // convert likliest paths into json
    // send to privcount over control port
    char* viterbi_result = NULL;
    control_event_privcount_viterbi(viterbi_result);

    tstream->magic = 0;
    tor_free_(tstream);
}

/* notify the traffic model that a stream transmitted a cell. */
void tmodel_stream_cell_transferred(tmodel_stream_t* tstream, tmodel_action_t action) {
    tor_assert(tstream && tstream->magic == TRAFFIC_STREAM_MAGIC);

    // TODO XXX
    // REMMEBER TO UPDATE PRIVCOUNT
    // to output state_space and observation_space
    // after the round ends
    // and update the model validation code?

    struct timeval transfer_time;
    tor_gettimeofday(&transfer_time);
}

// to emit event, call
//void control_event_privcount_viterbi()

// this is the form of the traffic model body coming in
// it looks like 'TRUE {}\r\n', where the {} is the following line
//{"states":["m0s2";"m0s11";"m0s5";"m0sEnd";"m0s12";"m0s8";"m0s7";"m0s9";"m0s4";"m0s13";"m0s15";"m0s14";"m0s3";"m0s10";"m0s1";"m0s0";"m0s6";"m1s0";"m1s12";"m1s9";"m1s15";"m1s1";"m1s4";"m1s14";"m1s13";"m1s8";"m1s11";"m1s5";"m1s6";"m1s3";"m1sEnd";"m1s2";"m2s0";"m2s4";"m2s5";"m2s8";"m2s10";"m2s3";"m2s6";"m2s7";"m2s2";"m2sEnd";"m2s1";"m2s11";"m2s9";"m3s6";"m3s1";"m3sEnd";"m3s2";"m3s3";"m3s8";"m3s14";"m3s0";"m3s7";"m3s12";"m3s4";"m3s5";"m3s15";"m3s9";"m3s10";"m3s11";"m4s13";"m4s5";"m4s9";"m4sEnd";"m4s10";"m4s3";"m4s4";"m4s12";"m4s0";"m4s6";"m4s7";"m4s8";"m4s1";"m4s2";"m4s11";"m4s14";"m5s14";"m5s13";"m5s4";"m5s6";"m5s7";"m5s10";"m5s9";"m5s5";"m5s2";"m5s11";"m5s1";"m5s8";"m5s12";"m5sEnd";"m5s0";"m6s1";"m6s8";"m6s3";"m6s6";"m6s4";"m6s2";"m6s7";"m6s9";"m6s5";"m6sEnd";"m6s10"];"emission_probability":{"m1s6":{"+":[0.010939649249180757;13.999999763708802;0.01];"-":[0.9890603507508193;5.1326143722028155;2.0751443522931985]};"m1s5":{"+":[0.6802762685957099;5.986558506074888;3.8556087518521496];"-":[0.31972373140429017;11.758608357839389;2.0780822206037617]};"m1s4":{"+":[0.3971745247006447;6.130164225667936;3.670383430203266];"-":[0.6028254752993554;0.6931471805599443;0.01]};"m1s3":{"+":[0.059921283701161315;9.598698928969446;2.507298346741341];"-":[0.9400787162988387;4.565974358136718;2.922021090949124]};"m1s2":{"-":[1.0;3.9426711195201927;1.3568069433177068]};"m1s1":{"-":[1.0;0.6931471805600146;0.01]};"m1s0":{"-":[1.0;3.378366236451709;2.2960840174026274]};"m1s9":{"+":[0.001476482802380788;6.999422467507961;0.01];"-":[0.9985235171976193;2.9957322735539993;0.01]};"m1s8":{"+":[0.23275524840240017;6.886743302334404;0.4702674349055173];"-":[0.7672447515975999;9.037740233423934;1.4920702074420324]};"m0sEnd":{"F":[1.0;10.183191288053328;4.020043044275213]};"m4s10":{"-":[1.0;10.999997633112407;0.01]};"m4s11":{"-":[1.0;1.555300804730652;0.8783208933285183]};"m4s12":{"+":[0.9789539814606759;4.952214890473033;2.464189815071575];"-":[0.021046018539324064;4.118549773244136;3.994922173482833]};"m4s13":{"+":[0.33333333333333337;1.809872281823449;1.2612260524196843];"-":[0.6666666666666667;9.890843713282452;3.958449272493786]};"m4s14":{"+":[1.0;1.9831764363517448;1.101589191895806]};"m3s9":{"+":[1.0;3.191409610279003;0.9016119885235871]};"m3s8":{"+":[1.0;4.12521000470585;2.328038058656329]};"m3sEnd":{"F":[1.0;13.91977461203617;2.2050893953416186]};"m5s9":{"+":[0.9338301338375816;9.310339466509543;1.3618278671899413];"-":[0.06616986616241835;4.219740675977248;3.2729478719184124]};"m5s8":{"+":[0.03171714718732423;9.04782091446962;1.3138563179976268];"-":[0.9682828528126758;8.280411031757424;2.8953879338749244]};"m5s2":{"-":[1.0;0.6931471805599454;0.01]};"m5s1":{"-":[1.0;0.6931471805599423;0.009999999999999998]};"m5s0":{"+":[0.9450553700850784;1.9721793914951076;1.626292081744794];"-":[0.054944629914921585;8.092434961750929;2.055710032769865]};"m5s7":{"+":[2.2736565911829896e-05;16.999999968802452;0.009999999999999998];"-":[0.9999772634340881;2.2665552332576047;1.2767745304808946]};"m5s6":{"+":[0.0002777906384555594;1.7371163209727518;0.46687719287501184];"-":[0.9997222093615444;8.41506146339043;2.3485391308101384]};"m5s5":{"-":[1.0;2.995732273554015;0.01]};"m5s4":{"+":[1.0;2.3817976531388987;1.8031849977128815]};"m6sEnd":{"F":[1.0;16.674184126156806;1.2398396598137364]};"m6s10":{"+":[1.0;2.8918378789563537;2.1600237865807137]};"m5s14":{"+":[1.0;6.337458026164865;0.8203823297285975]};"m5s13":{"+":[0.043351607954746976;8.496518227841419;2.03362166849406];"-":[0.956648392045253;1.9763770625064008;1.2850387028407526]};"m5s12":{"-":[1.0;3.988984046564273;0.009999999999999998]};"m5s11":{"+":[1.0;7.851961177703812;3.773017962128586]};"m5s10":{"-":[1.0;0.6931471805599453;0.01]};"m1s13":{"-":[1.0;11.553233130647792;0.5434143574035668]};"m1s12":{"-":[1.0;4.294777087054357;2.2706029443599927]};"m1s11":{"-":[1.0;0.6931471805600233;0.01]};"m1s15":{"-":[1.0;4.568194606678242;2.890296035402213]};"m1s14":{"-":[1.0;1.9459101490554116;0.01]};"m3s1":{"+":[0.6713342105913138;10.50169060974096;3.6332398068019036];"-":[0.32866578940868624;5.84067944219178;4.230584002914137]};"m3s0":{"+":[0.0009180579781660277;1.4126943954804616;0.9346394203541686];"-":[0.9990819420218339;4.877418313992135;3.271791271390003]};"m3s3":{"-":[1.0;0.6931471805597643;0.01]};"m3s2":{"-":[1.0;2.2658743204938867;1.6373636942159178]};"m3s5":{"-":[1.0;0.6931471805599481;0.01]};"m3s4":{"+":[0.00020284333194100997;1.5469874330787494;0.7421702551906709];"-":[0.9997971566680589;2.9333716400918632;0.9999983140598697]};"m3s7":{"-":[1.0;2.902323781631883;2.2870799325150153]};"m3s6":{"+":[0.7896357316760548;10.725006314637087;3.408481747840961];"-":[0.2103642683239452;9.725153206894419;1.4533268715861396]};"m4s8":{"-":[1.0;3.019089967949886;1.6998622043957567]};"m4s9":{"+":[1.0;8.101499967003427;0.34373335793679444]};"m1sEnd":{"F":[1.0;4.527748983839587;2.2678180925632656]};"m4s2":{"+":[6.584702794736e-05;7.999678579499451;0.01];"-":[0.9999341529720527;2.0686536930876587;0.8820345163050397]};"m4s3":{"+":[0.9961708719802569;4.110298254267704;1.2592147800766151];"-":[0.0038291280197431644;5.693685939675946;4.1976275691280485]};"m4s0":{"+":[0.21537147736976944;1.5141091861023983;1.18004576410213];"-":[0.7846285226302306;3.51614645306408;1.505840742770918]};"m4s1":{"+":[0.9948509481548512;7.735784747941672;2.2747402950129048];"-":[0.005149051845148891;11.368416747829604;0.9846490686672437]};"m4s6":{"+":[1.0;4.1307037462191785;0.8416873776074199]};"m4s7":{"+":[0.992577376059042;4.145502184812064;1.7706757533933373];"-":[0.007422623940957987;7.405593662994284;5.01835101448898]};"m4s4":{"+":[0.9941577408604229;4.804184864261106;2.171568674693005];"-":[0.005842259139577084;2.019958203824334;1.1877394593950856]};"m4s5":{"-":[1.0;2.051062998454741;1.276369571791786]};"m6s4":{"+":[0.50733029444376;9.217801947701217;1.9141762676468566];"-":[0.49266970555624007;5.418451383953838;1.4077597245393316]};"m6s5":{"+":[1.0;5.0502222842829605;1.7332724635249663]};"m6s6":{"-":[1.0;11.234573492177212;0.9540886418791527]};"m6s7":{"+":[0.23344361576851902;2.9103046479080508;1.7517512921332694];"-":[0.7665563842314811;11.441181608825945;0.4965275160596036]};"m6s1":{"-":[1.0;2.148123594793602;1.6212400816362569]};"m6s2":{"-":[1.0;2.03211941910644;1.3372291050958822]};"m6s3":{"-":[1.0;1.2512102867415764;0.7080548319307012]};"m6s8":{"-":[1.0;1.665038893087571;0.9976098390021542]};"m6s9":{"+":[0.9566815963633933;9.340850325633985;2.6021365752006598];"-":[0.04331840363660673;16.627314688749355;1.1679867258788088]};"m2sEnd":{"F":[1.0;9.920984940453248;1.5821277908748395]};"m2s10":{"+":[1.0;9.08511919262242;0.2852193275181275]};"m2s11":{"-":[1.0;8.969695611812762;3.1410229154376887]};"m0s6":{"+":[0.002409239809440606;0.6931471805599457;0.01];"-":[0.9975907601905595;8.694326888042378;2.608423899658795]};"m0s7":{"-":[1.0;1.3293419450897175;0.8299221323903758]};"m0s4":{"+":[0.8603692789196117;7.586842505856025;3.44328647271633];"-":[0.1396307210803884;7.325817975624356;3.4494657962959683]};"m0s5":{"+":[0.6320803586013917;7.419244057957895;3.8434761720542205];"-":[0.3679196413986083;9.34441593517758;3.940394442602817]};"m0s2":{"+":[1.0;3.0511182299222277;1.792722927350526]};"m0s3":{"+":[3.227894170261734e-05;2.7139787114284957;0.9045375818134501];"-":[0.9999677210582975;1.9898361977214711;1.2122689122852806]};"m0s0":{"+":[0.8099801787719907;11.999995137340928;0.01];"-":[0.1900198212280093;5.516149605954191;3.0706394584396577]};"m0s1":{"+":[0.0007119654653736085;3.8418886024501258;1.7415365035432582];"-":[0.9992880345346263;1.3620391452794036;0.8810156529601049]};"m0s8":{"-":[1.0;1.475767511602623;0.9249477290425022]};"m0s9":{"+":[0.0016864532744350939;1.9459101490553097;0.01];"-":[0.9983135467255648;1.5430843370030616;0.9911095795232491]};"m3s11":{"+":[1.0;0.8696144676452224;0.4358958343344941]};"m3s10":{"+":[1.0;5.358620283993609;1.5201529981455322]};"m3s12":{"-":[1.0;7.035581505483467;2.7171391712143875]};"m3s15":{"-":[1.0;1.945910149055387;0.01]};"m3s14":{"+":[0.00019277250187282413;6.081999981654045;3.7818660167938134];"-":[0.999807227498127;4.053195936959341;2.141338092427437]};"m2s0":{"+":[0.8324293181222403;11.01293247004973;1.0567235379759865];"-":[0.16757068187775967;12.709675271472248;0.520147463367743]};"m2s1":{"+":[1.0;11.725441516614305;0.6412727101923817]};"m2s2":{"+":[1.0;2.837056304505527;1.9266093414570766]};"m2s3":{"+":[0.2781048610316234;10.948677153063754;1.6232632656213284];"-":[0.7218951389683766;6.899720267138424;1.3485214600263886]};"m2s4":{"+":[0.19655024902167295;8.281073927186304;2.647124611662931];"-":[0.803449750978327;6.058101949710143;3.988507744522249]};"m2s5":{"+":[0.23858316806304264;4.294816852688886;3.1950296654401624];"-":[0.7614168319369573;10.367014330781762;1.8696823086471939]};"m2s6":{"-":[1.0;0.937439330562447;0.5009256771907029]};"m2s7":{"+":[1.0;1.3064689719970444;0.9693114636639333]};"m2s8":{"-":[1.0;8.70024006204888;3.2376785022543095]};"m2s9":{"-":[1.0;1.093125405365795;0.7067327465850565]};"m0s14":{"-":[1.0;1.5397435411284706;0.9838405244623166]};"m0s15":{"+":[1.0;0.6931471805598993;0.01]};"m0s10":{"-":[1.0;1.6110859061291167;1.2538943176005322]};"m0s11":{"+":[0.4476114185871532;11.268064272130253;1.8299198626362292];"-":[0.5523885814128469;9.024045347492311;3.7931998314930215]};"m0s12":{"-":[1.0;4.694467939194742;3.5792631222126476]};"m0s13":{"+":[0.6669969634810282;4.976429343467929;2.582980845440365];"-":[0.3330030365189717;11.643850705980519;0.49200668861893565]};"m5sEnd":{"F":[1.0;9.709193020882996;1.7750774170228905]};"m4sEnd":{"F":[1.0;1.1131382064066822;0.8964261852898402]}};"transition_probability":{"m1s6":{"m1s6":0.5733545015159799;"m1s5":0.23207668050564764;"m1s0":0.19456881797837247};"m1s5":{"m1s13":0.2833405108099692;"m1s4":0.43478635696830076;"m1s3":0.13185154170020114;"m1sEnd":0.1500215905215289};"m1s4":{"m1s5":0.4079010158634797;"m1s15":0.5902286019777352;"m1s8":0.0018703821587850846};"m1s3":{"m1s4":0.3127249374666302;"m1s3":0.0724302908807396;"m1sEnd":0.039485594615649315;"m1s0":0.5753591770369809};"m1s2":{"m1s6":0.9428570086031445;"m1sEnd":0.057142991396855525};"m1s1":{"m1s3":0.44436717540108567;"m1sEnd":0.0018825647899673725;"m1s1":0.553750259808947};"m1s0":{"m1s12":0.2563565679894107;"m1s5":0.010516285039345454;"m1s1":0.38871016729422875;"m1s14":0.34441697967701507};"m1s9":{"m1s0":1.0};"m1s8":{"m1s3":0.01799452340585254;"m1s8":0.9820054765941475};"m0sEnd":{};"m4s10":{"m4s11":0.021021021021021023;"m4s9":0.033283283283283276;"m4s7":0.024399399399399394;"m4sEnd":0.9212962962962963};"m4s11":{"m4s8":0.05;"m4s5":0.95};"m4s12":{"m4s10":0.004947384955139612;"m4s3":0.9711533427483394;"m4s13":0.023611329256803856;"m4sEnd":0.0002879430397171205};"m4s13":{"m4s2":0.4192176870748299;"m4sEnd":0.14540816326530612;"m4s5":0.43537414965986393};"m4s14":{"m4s3":0.0004587565229212763;"m4s1":0.0620765496262478;"m4s14":0.937464693850831};"m3s9":{"m3s0":0.027420948616603255;"m3s4":0.0009881422924901157;"m3s8":0.9715909090909066};"m3s8":{"m3s1":0.22908721078057462;"m3s11":0.7709127892194254};"m3sEnd":{};"m5s9":{"m5s9":0.0007871127019644998;"m5sEnd":0.0034632958886437995;"m5s8":0.15742254028593006;"m5s0":0.24589363253531643;"m5s6":0.4890592840528954;"m5s4":0.10337413453524981};"m5s8":{"m5s1":0.2636382306463823;"m5s14":0.030703265577777538;"m5s9":0.7056585037758403};"m5s2":{"m5s1":0.9215686274509803;"m5s12":0.07843137254901959};"m5s1":{"m5s1":0.3966672976324816;"m5s5":0.6033327023675183};"m5s0":{"m5s9":0.05516270212493483;"m5s8":0.08921715915915662;"m5s6":0.5775217824410872;"m5s4":0.27809835627482127};"m5s7":{"m5s7":0.7611295734023767;"m5s13":0.23698325910944804;"m5s11":0.001887167488175182};"m5s6":{"m5s7":0.48641154058881136;"m5sEnd":0.1870456964651932;"m5s13":0.3216814267730232;"m5s12":0.0037038751794074578;"m5s11":0.0011574609935648304};"m5s5":{"m5sEnd":0.03760692979344534;"m5s2":0.04358985044240256;"m5s9":0.2188015055998506;"m5s6":0.7000017141643013};"m5s4":{"m5sEnd":0.0008837825906843235;"m5s0":0.9953601413989073;"m5s11":0.0037560760104083744};"m6s10":{"m6s6":1.0};"m5s14":{"m5s8":1.0};"m5s13":{"m5sEnd":0.28893337154468746;"m5s9":0.35922202677566484;"m5s6":0.35184460167964765};"m5s12":{"m5s10":1.0};"m5s11":{"m5sEnd":0.041109473310679524;"m5s13":0.002356228636994876;"m5s11":0.9565342980523256};"m5s10":{"m5s5":1.0};"m1s13":{"m1s6":0.12658023838294882;"m1s3":0.5447068479523111;"m1s0":0.32871291366474015};"m1s12":{"m1s11":1.0};"m1s11":{"m1s12":0.6860950840156506;"m1s0":0.3139049159843494};"m1s15":{"m1s4":0.24719716838464434;"m1s2":0.045824609165570684;"m1s9":0.15139709222887468;"m1s0":0.5555811302209103};"m1s14":{"m1s4":0.16852967712663963;"m1s15":0.13256271946235162;"m1s0":0.6989076034110088};"m3s1":{"m3sEnd":0.22654054523787778;"m3s10":0.01963468993566476;"m3s12":0.021688400436259116;"m3s1":0.010994602260123524;"m3s0":0.24395555429621688;"m3s6":0.47718620783385796};"m3s0":{"m3s3":0.1573650989282394;"m3s14":0.3261667981104009;"m3s7":0.5164681029613596};"m3s3":{"m3s0":0.17504932290258415;"m3s2":0.8230655252860325;"m3s7":0.0018851518113834058};"m3s2":{"m3s3":0.6630200133287677;"m3s15":0.21715625941308891;"m3s4":0.11982372725814347};"m3s5":{"m3s0":1.0};"m3s4":{"m3sEnd":0.014437158496308486;"m3s10":0.0032984089628668575;"m3s12":0.11303666602416282;"m3s2":0.8692277665166618};"m3s7":{"m3s1":0.12651463104107347;"m3s3":0.8734853689589264};"m3s6":{"m3s1":0.9380265321578641;"m3s15":0.061973467842135734};"m4s8":{"m4s0":0.8652283138761637;"m4s12":0.13477168612383628};"m4s9":{"m4s10":0.9903541058509964;"m4s12":0.0011422769386978044;"m4s13":0.007488259931463382;"m4s4":0.0010153572788424924};"m4s2":{"m4s2":0.9953624878888502;"m4s11":0.002746761737232733;"m4s1":0.0006678769977517941;"m4s9":0.0012228733761652576};"m4s3":{"m4s4":1.0};"m4s0":{"m4s8":0.9511528608027328;"m4s7":0.048847139197267284};"m4s1":{"m4s6":0.5402438708438865;"m4s12":0.06768293149076776;"m4s14":0.3767615434942452;"m4s8":0.015311654171100652};"m4s6":{"m4s3":0.008916825780297242;"m4s6":0.9910809371833466;"m4s7":2.2370363562755323e-06};"m4s7":{"m4s12":0.993755135577349;"m4s13":0.005888797591534937;"m4sEnd":0.0003560668311160659};"m4s4":{"m4s14":0.20273079562449023;"m4s7":0.7972692043755097};"m4s5":{"m4s8":1.0};"m6s4":{"m6s5":0.024516446963163734;"m6s1":0.06406307749168413;"m6s2":0.08069483799433275;"m6s9":0.8307256375508195};"m6s5":{"m6s4":0.0012323889146926765;"m6s5":0.9987676110853073};"m6s6":{"m6sEnd":0.29057222082177964;"m6s4":0.03609780690698261;"m6s6":0.04023191328459793;"m6s1":0.09654650869674815;"m6s3":0.1275775144945803;"m6s8":0.2514746659944543;"m6s9":0.15749936980085708};"m6s7":{"m6s4":0.19273257444064368;"m6s9":0.8072674255593564};"m6s1":{"m6sEnd":0.3621322207035466;"m6s6":0.20250341702035826;"m6s9":0.4353643622760952};"m6s2":{"m6s1":0.2907152984892192;"m6s2":0.7092847015107809};"m6s3":{"m6s1":0.23515328855489792;"m6s2":0.351865398683248;"m6s9":0.4129813127618541};"m6s8":{"m6s3":1.0};"m6s9":{"m6sEnd":0.06059897051941974;"m6s10":0.1446119393007554;"m6s4":0.05095594625309178;"m6s6":0.44464870646433585;"m6s7":0.29803128551373753;"m6s1":0.0011531519486596695};"m2sEnd":{};"m2s10":{"m2s11":0.28351262668765187;"m2s5":0.716487373312348};"m2s11":{"m2s9":0.05717130339206509;"m2s10":0.0875448958103994;"m2s3":0.025780270200685993;"m2s4":0.06150852223269988;"m2s6":0.7679950083641496};"m0s6":{"m0s14":0.3922292917609632;"m0s9":0.5039125590520771;"m0s1":0.10385814918695967};"m0s7":{"m0s6":0.98512390215163;"m0s3":0.01487609784836996};"m0s4":{"m0s0":0.06223960700196126;"m0s13":0.9377603929980387};"m0s5":{"m0s15":0.09174606187792429;"m0s4":0.6647588770944839;"m0sEnd":0.08763508357211966;"m0s11":0.15585997745547212};"m0s2":{"m0s6":0.15550238364730273;"m0s15":0.23184304553154347;"m0s5":0.014303942459307807;"m0s2":0.524839848754298;"m0s11":0.073510779607548};"m0s3":{"m0s6":0.0061071757701352;"m0s3":0.9932561221047805;"m0s1":0.0006367021250841273};"m0s0":{"m0s2":0.7500078704519266;"m0s12":0.2499921295480733};"m0s1":{"m0s10":0.4669010171316463;"m0s11":0.5330989828683538};"m0s8":{"m0s14":0.9380719778131518;"m0s1":0.06192802218684825};"m0s9":{"m0s14":0.7002398892959711;"m0sEnd":0.030445212578496063;"m0s4":0.021818141372229594;"m0s5":0.03077916372276963;"m0s0":0.10033561953816035;"m0s1":0.11638197349237313};"m3s11":{"m3s10":0.9981966634436823;"m3s6":0.0018033365563176597};"m3s10":{"m3s11":0.9388270140389584;"m3s9":0.06117298596104165};"m3s12":{"m3s12":0.275396115051875;"m3s5":0.7246038849481249};"m3s15":{"m3s7":1.0};"m3s14":{"m3s1":0.006120526935017157;"m3s14":0.8300969826423049;"m3s4":0.16378249042267784};"m2s0":{"m2s3":0.7459412877169052;"m2s5":0.2540587122830948};"m2s1":{"m2s7":1.0};"m2s2":{"m2s2":0.5999888968124577;"m2s3":0.4000111031875422};"m2s3":{"m2s10":0.015833444394669497;"m2s2":0.0034551663053829264;"m2s3":0.8531762580957591;"m2s5":0.04289360977446942;"m2s6":0.06261747035126024;"m2s9":0.022024051078458656};"m2s4":{"m2s3":0.010276035383052134;"m2s4":0.9857671464757269;"m2s7":0.003956818141220903};"m2s5":{"m2s8":0.2900401696383759;"m2sEnd":0.7092915280424885;"m2s7":0.00066830231913551};"m2s6":{"m2s8":0.05098862435568371;"m2s9":0.1989865234631587;"m2s10":0.01918298395403538;"m2sEnd":0.07842196628010695;"m2s6":0.6524199019470153};"m2s7":{"m2s11":0.19172267011266195;"m2s5":0.14998232161533437;"m2s7":0.6582950082720036};"m2s8":{"m2s9":0.24132080552459656;"m2s11":0.09256096737597404;"m2sEnd":0.6369187325649514;"m2s6":0.02919949453447794};"m2s9":{"m2s0":0.06567156766856526;"m2s1":0.31807047214582473;"m2s11":0.6162579601856101};"m0s14":{"m0s7":0.1705102952708992;"m0s8":0.8294897047291009};"m0s15":{"m0s15":0.40209176653572354;"m0s2":0.5979082334642765};"m0s10":{"m0s4":0.13973251219958288;"m0sEnd":0.21831120241616123;"m0s0":0.6419562853842559};"m0s11":{"m0s6":0.2550192463086928;"m0s5":0.04870014177660558;"m0s11":0.570650213390658;"m0sEnd":0.1158436966406641;"m0s3":0.009786701883379394};"m0s12":{"m0s3":0.002221832943539733;"m0s12":0.9724464968480889;"m0s1":0.02533167020837134};"m0s13":{"m0s6":0.14100330875085648;"m0s5":0.8414332053244805;"m0s3":0.0008789733629267396;"m0sEnd":0.016684512561736337};"m5sEnd":{};"m4sEnd":{}};"start_probability":{"m1s5":0.01825468701423338;"m1s4":0.02110677065733094;"m4s9":0.050573795974642136;"m2s10":0.030724104837728597;"m4s1":0.0005068869033941146;"m0s11":0.49732363715007905;"m5s11":0.013368297265514117;"m1s8":0.0003717170624890175;"m5s9":0.06229302118111406;"m2s3":0.00394020086238359;"m0s0":0.006427325935037376;"m3s1":0.09572052283694461;"m6s9":0.13643367891755992;"m3s6":0.06295535340154905}}

//def _store_new_packet_bundle(self, circuit_id, stream_id, is_sent,
//        micros_since_prev_cell, bundle_ts, payload_bytes_last_packet):
//    num_packets = 1
//    packet_bundle = [is_sent, micros_since_prev_cell, bundle_ts,
//                    num_packets, payload_bytes_last_packet]
//    self.packets.setdefault(circuit_id, {}).setdefault(stream_id, []).append(packet_bundle)
//
//    # store an entry so we can evict the stream if it persists for too long
//    if len(self.packets[circuit_id][stream_id]) == 1:
//        # min heap sorted by time (the first element in the tuple)
//        entry = (bundle_ts, circuit_id, stream_id)
//        heappush(self.pheap, entry)
//
//def _clear_expired_bundles(self):
//    cleanup_count = 0
//
//    while len(self.pheap) > 0:
//        entry = self.pheap[0] # peek the next entry
//        bundle_ts, circuit_id, stream_id = entry
//
//        # check if the next item in the min heap expired
//        # if streams are STREAM_EVICT_TIME seconds old, clear them
//        if time() - bundle_ts >= TrafficModel.STREAM_EVICT_TIME:
//            # remove the heap entry
//            heappop(self.pheap)
//
//            # check if we are still actually storing the packet bundles
//            if circuit_id in self.packets:
//                if stream_id in self.packets[circuit_id]:
//                    # we are storing the stream data yet, clear it now
//                    # TODO: secure delete?
//                    self.packets[circuit_id].pop(stream_id, None)
//                    cleanup_count += 1
//                # clear out any leftover empty circuit keys
//                if len(self.packets[circuit_id]) == 0:
//                    self.packets.pop(circuit_id, None)
//        else:
//            break
//
//    if cleanup_count > 0:
//        desc = "stream" if cleanup_count == 1 else "streams"
//        logging.info("cleared stale packet bundles on {} {}".format(cleanup_count, desc))
//
//def handle_cell(self, circuit_id, stream_id, is_sent, payload_bytes, cell_ts):
//    # is_sent=True means a cell was sent toward the client side
//    # is_sent=False means a cell was received from the client side
//
//    if circuit_id not in self.packets or stream_id not in self.packets[circuit_id]:
//        # this is the first packet on the stream
//        self._store_new_packet_bundle(circuit_id, stream_id, is_sent, long(0), cell_ts, payload_bytes)
//    else:
//        # we already had some packets.
//        # lets figure out if we can add the new cell to the previous bundle,
//        # or if we need to start a new bundle.
//        prev_packet_bundle = self.packets[circuit_id][stream_id][-1]
//
//        secs_since_prev_cell = cell_ts - prev_packet_bundle[2]
//        micros_since_prev_cell = max(long(0), long(secs_since_prev_cell * 1000000))
//
//        if is_sent == prev_packet_bundle[0] and \
//                micros_since_prev_cell <= TrafficModel.PACKET_ARRIVAL_TIME_TOLERENCE:
//            # cell occured at the same time as the previous,
//            # lets assume it arrived in the same packet
//            prev_packet_bundle[4] += payload_bytes
//            while prev_packet_bundle[4] > TrafficModel.PACKET_BYTE_COUNT:
//                spillover = prev_packet_bundle[4] - TrafficModel.PACKET_BYTE_COUNT
//                prev_packet_bundle[3] += 1
//                prev_packet_bundle[4] = spillover
//
//        else:
//            # cell direction or time is different, need a new bundle
//            self._store_new_packet_bundle(circuit_id, stream_id, is_sent,
//                    micros_since_prev_cell, cell_ts, payload_bytes)
//
//def handle_stream(self, circuit_id, stream_id, stream_end_ts, secure_counters):
//    # use our observations to find the most likely path through the HMM,
//    # and then count some aggregate statistics about that path
//
//    if circuit_id in self.packets:
//        if stream_id in self.packets[circuit_id]:
//            # get the list of packet bundles
//            bundles = self.packets[circuit_id].pop(stream_id)
//            if bundles is not None and len(bundles) > 0:
//                # add the ending state
//                prev_packet_bundle = bundles[-1]
//
//                secs_since_prev_cell = stream_end_ts - prev_packet_bundle[2]
//                micros_since_prev_cell = max(long(0), long(secs_since_prev_cell * 1000000))
//
//                end_bundle = [None, micros_since_prev_cell, stream_end_ts, 1, 0]
//                bundles.append(end_bundle)
//
//                # we log a warning here in case PrivCount hangs in vitterbi
//                # (it could hang processing packets, but that's very unlikely)
//                stream_packet_count = sum(bundle[3] for bundle in bundles)
//                if stream_packet_count > TrafficModel.MAX_STREAM_PACKET_COUNT:
//                    # round the packet count to the nearest
//                    # TrafficModel.MAX_STREAM_PACKET_COUNT, for at least a little user
//                    # protection
//                    rounded_stream_packet_count = TrafficModel._integer_round(
//                                                  stream_packet_count,
//                                                  TrafficModel.MAX_STREAM_PACKET_COUNT)
//                    logging.info("Large stream packet count: ~{} packets in {} bundles. Stream packet limit is {} packets."
//                                 .format(rounded_stream_packet_count,
//                                         len(bundles),
//                                         TrafficModel.MAX_STREAM_PACKET_COUNT))
//
//                # run viterbi to get the likliest path through our model given the observed delays
//                viterbi_start_time = clock()
//                likliest_states = self._run_viterbi(bundles)
//
//                # increment result counters
//                counter_start_time = clock()
//                if likliest_states is not None and len(likliest_states) > 0:
//                    self._increment_traffic_counters(bundles, likliest_states, secure_counters)
//
//                algo_end_time = clock()
//                algo_elapsed = algo_end_time - viterbi_start_time
//                viterbi_elapsed = counter_start_time - viterbi_start_time
//                counter_elapsed = algo_end_time - counter_start_time
//
//                if algo_elapsed > TrafficModel.MAX_STREAM_PROCESSING_TIME:
//                    rounded_num_packets = TrafficModel._integer_round(
//                                                  stream_packet_count,
//                                                  TrafficModel.MAX_STREAM_PACKET_COUNT)
//                    logging.warning("Long stream processing time: {:.1f} seconds to process ~{} packets exceeds limit of {:.1f} seconds. Breakdown: viterbi {:.1f} counter {:.1f}."
//                                    .format(algo_elapsed, rounded_num_packets,
//                                            TrafficModel.MAX_STREAM_PROCESSING_TIME,
//                                            viterbi_elapsed, counter_elapsed))
//                # TODO: secure delete?
//                #del likliest_states
//            # TODO: secure delete?
//            #del bundles
//
//        if len(self.packets[circuit_id]) == 0:
//            self.packets.pop(circuit_id, None)
//
//    # take this opportunity to clear any streams that stuck around too long
//    self._clear_expired_bundles()
